class CookieUpgrader
  COOKIE_UPGRADER_ENABLED = "COOKIE_UPGRADER_ENABLED".freeze
  HTTP_COOKIE = "HTTP_COOKIE".freeze
  HTTP_HOST = "HTTP_HOST".freeze
  HTTP_X_COOKIE_UPGRADER = "HTTP_X_COOKIE_UPGRADER".freeze

  def initialize(app, cookie_map)
    @app = app
    @cookie_map = cookie_map.deep_symbolize_keys!
  end

  def call(env)
    before_call(env)
    @app.call(env).tap { after_call(env) }
  end

  private

  # We need to upgrade old session cookies. Before unforking, we had two sites, two
  # different settings for the encryption and how the domain attribute of the
  # cookie was labelled, possibly causing multiple session cookies with the same
  # name being sent to the site and not allowing logins to work.
  #
  # The new production site has a differently named session cookie, so we can
  # distinguish between the two.
  #
  # If we only get the old session cookie in the HTTP_COOKIE header, then we will
  # decrypt that, re-encrypt it with the current production settings and replace
  # that part of the cookie header, upgrading the cookie and from there on out
  # everything should work normally.
  def before_call(env)
    if enabled?(env)
      @host = env[HTTP_HOST].split(":").first
      enc_config = EncryptionConfig.build_from_env(env)
      new_cookie_header = cookie_swapper(enc_config).swap(env[HTTP_COOKIE], old_key, old_secret_key_base, @host)
      env[HTTP_COOKIE] = new_cookie_header if new_cookie_header
    end
  rescue Exception # rubocop:disable Lint/RescueException
    stats_count("exception") rescue nil # rubocop:disable Style/RescueModifier
    # don't f with rack
  end

  def enabled?(env)
    ENV[COOKIE_UPGRADER_ENABLED] == "true" || env[HTTP_X_COOKIE_UPGRADER]
  end

  # In the future we may make sure the old session cookie is marked for deletion
  # (see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie) for
  # details on how to set Expires or Max-Age appropriately to tell the browser to
  # remove it.
  def after_call(env)
  end

  def log(message)
    Rails.logger.info("CookieUpgrader: #{message}") rescue nil # rubocop:disable Style/RescueModifier
  end

  def old_secret_key_base
    upgrader_settings_for_host[:old_secret_key_base]
  end

  def old_key
    upgrader_settings_for_host[:old_session_cookie_key]
  end

  def upgrader_settings_for_host
    @cookie_map[@host.to_sym]
  end

  def cookie_swapper(request)
    @cookie_swapper ||= CookieSwapper.new(request)
  end

  class CookieSwapper
    def initialize(encryption_config,
                   new_key = Rails.application.config.session_options[:key],
                   new_secret_key_base = Rails.application.secrets[:secret_key_base])
      @encryption_config = encryption_config
      @new_key = new_key
      @new_secret_key_base = new_secret_key_base
    end

    # It's very important for this method to return nil or a valid new encrypted session cookie value!
    # Otherwise, the user will likely be logged out of their session.
    def swap(cookie_header, old_key, old_secret_key_base, host)
      @host = host

      if cookie_header.empty?
        stats_count("no_cookie_header")
        return
      end

      @all = CookieHeader.to_hash(cookie_header)
      @old_key = old_key
      @old_secret_key_base = old_secret_key_base

      upgrade_if_needed
    end

    private

    # It's very important for this method to return nil or a valid new encrypted session cookie value!
    # I know the `return` keywords are redundant in this method, but it gives me some peace of mind on
    # top of the tests.
    def upgrade_if_needed
      new_session_cookies = @all[@new_key]
      if new_session_cookies
        stats_count("has_new_cookie")
        return nil
      else
        session_data = decrypt_old_sessions.first
        if session_data
          stats_count("cookie_upgraded")
          @all[@new_key] = new_elf.encrypt_session(session_data)
          log("old | #{@old_key}=#{@all[@old_key]}")
          log("new | #{@new_key}=#{@all[@new_key]}")
          @all.delete(@old_key)
          return CookieHeader.to_string(@all)
        else
          log("old could not be decrypted | #{@old_key}=#{@all[@old_key]}")
          stats_count("cookie_not_upgraded")
          return nil
        end
      end
    end

    def decrypt_old_sessions
      @all[@old_key].map do |old_session_cookie|
        # nil is returned if decrypting fails
        host_old_elf.decrypt_session(old_session_cookie)
      end.compact
    end

    def host_old_elf
      @elves ||= {}
      @elves[@old_secret_key_base] ||= CookieEncryptor.new(encryption_config(@old_secret_key_base))
    end

    def new_elf
      @new_elf ||= CookieEncryptor.new(encryption_config(@new_secret_key_base))
    end

    def encryption_config(secret_key_base)
      @encryption_config.dup.tap { |ec| ec.secret_key_base = secret_key_base }
    end

    def stats_count(name)
      Stats.count("cookie_upgrader.#{name}", 1, @host)
    end

    def log(message)
      Rails.logger.info("CookieUpgrader: #{@host} #{message}") rescue nil # rubocop:disable Style/RescueModifier
    end
  end

  public

  class CookieHeader
    # Keys MAY have multiple values, browsers can pass up the same cookie key
    # if they have different Domain attributes (.mysteryscience.com vs.
    # mysteryscience.com) or varying scopes of Path attribute. Implementation
    # here is based on Rack::Request#cookies.
    #
    # It differs in that we'll keep all values of the same key, whereas Rack
    # keeps the first, based on some RFC language that says in some instances
    # only the first should be kept.
    #
    #    If multiple cookies satisfy the criteria above, they are ordered in
    #    the Cookie header such that those with more specific Path attributes
    #    precede those with less specific.  Ordering with respect to other
    #    attributes (e.g., Domain) is unspecified.
    #
    # NOTE: That language is from the 1997 RFC. There have been two more since,
    # the most recent being in 2011, which, as I understand it, was written
    # to help correct prior RFCs according to how most things were actually
    # implemented in Real Life(TM). All that to say: YMMV.
    def self.to_hash(string)
      hash = {}

      cookies = Rack::Utils.parse_query(string, ";,") { |s| Rack::Utils.unescape(s) rescue s } # rubocop:disable Style/RescueModifier
      cookies.each { |k, v| hash[k] = Array(v) }
      hash
    end

    def self.to_string(hash)
      result_ary = hash.each_with_object([]) do |(key, values), ary|
        values = Array(values)
        values.each do |value|
          ary << "#{key}=#{value}"
        end
      end
      result_ary.join("; ")
    end
  end

  class CookieEncryptor
    def initialize(encryption_config)
      # The number of iterations used here matches what Rails uses elsewhere and is
      # also hardcoded. For future versions of Rails, this will need to be checked.
      key_gen = ActiveSupport::KeyGenerator.new(encryption_config.secret_key_base, iterations: 1000)
      key_gen = ActiveSupport::CachingKeyGenerator.new(key_gen) # Rails uses this, why not us?
      encryption_config.key_generator = key_gen
      @parent = ActionDispatch::Cookies::CookieJar.new(encryption_config)

      @encrypted_jar = ActionDispatch::Cookies::EncryptedCookieJar.new(@parent)
    end

    def encrypt_session(session_hash)
      # The code in the encrypted jar expects to receive an entire cookie hash
      # not just the value of the session cookie.
      @encrypted_jar["session"] = {value: session_hash}
      @parent["session"]
    end

    def decrypt_session(encrypted)
      @parent["session"] = encrypted
      @encrypted_jar["session"]
    end
  end

  class EncryptionConfig
    attr_accessor :cookies_digest,
                  :cookies_serializer,
                  :encrypted_cookie_salt,
                  :encrypted_signed_cookie_salt,
                  :key_generator,
                  :secret_key_base

    # 4.2 had Cookies.options_from_env, but it was renamed then removed during 5.0 development:
    # https://github.com/rails/rails/commit/e6074a35412b85c4c27a7d8063c68370617e3daa
    def self.build_from_env(env)
      new.tap do |ec|
        ec.cookies_digest = env[ActionDispatch::Cookies::COOKIES_DIGEST]
        ec.cookies_serializer = env[ActionDispatch::Cookies::COOKIES_SERIALIZER]
        ec.encrypted_cookie_salt = env[ActionDispatch::Cookies::ENCRYPTED_COOKIE_SALT]
        ec.encrypted_signed_cookie_salt = env[ActionDispatch::Cookies::ENCRYPTED_SIGNED_COOKIE_SALT]
        ec.key_generator = env[ActionDispatch::Cookies::GENERATOR_KEY]
        ec.secret_key_base = env[ActionDispatch::Cookies::SECRET_KEY_BASE]
      end
    end
  end
end
