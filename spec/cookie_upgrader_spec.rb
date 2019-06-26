require "rails_helper"

RSpec.describe "CookieUpgrader", :type => :request do
  fixtures :grade_systems, :grades

  let(:upgrader_config) { YAML.load_file(Rails.root.join("config", "cookie_upgrader.yml"))[Rails.env] }
  let(:md_secret) { upgrader_config["mysterydoug.com"]["old_secret_key_base"] }
  let(:ms_secret) { upgrader_config["mysteryscience.com"]["old_secret_key_base"] }
  let!(:mystery) { MysteryFixture.create }
  let(:legacy_md_crypt) { CookieUpgrader::CookieEncryptor.new(encrypt_config(md_secret)) }
  let(:legacy_ms_crypt) { CookieUpgrader::CookieEncryptor.new(encrypt_config(ms_secret)) }
  let(:new_crypt) { CookieUpgrader::CookieEncryptor.new(default_enc_config) }
  let(:password) { "Passw0rd!" }
  let(:md_user) { UserFixture.signed_up.create(origin: "mysterydoug", password: password) }
  let(:ms_user) { UserFixture.create(origin: "mysteryscience") }
  let(:session_id) { SecureRandom.hex }

  it "ensure crypt is working" do
    expect(legacy_md_crypt.decrypt_session(legacy_md_crypt.encrypt_session("bob"))).to eq "bob"
  end

  context "mysterydoug.com" do
    before do
      host! "mysterydoug.com"
    end

    it "login with no existing cookie" do
      headers = {"X-COOKIE-UPGRADER" => "true"}
      get "/", params: {}, headers: headers
      cookie = response.cookies["_m_session_id"]
      decrypted_session = new_crypt.decrypt_session(cookie)

      login_params = {authenticity_token: decrypted_session["_csrf_token"],
                      email: md_user.email, password: password}

      post "/log-in", params: login_params, headers: headers
      expect(response).to redirect_to "/"
    end

    it "login with legacy session cookie redirects to home page" do
      cookies["_session_id"] = legacy_md_crypt.encrypt_session({session_id: session_id, current_user_id: md_user.id})
      headers = {"X-COOKIE-UPGRADER" => "true"}
      get "/log-in", params: {}, headers: headers
      cookie = response.cookies["_m_session_id"]
      decrypted_session = new_crypt.decrypt_session(cookie)
      expect(decrypted_session["current_user_id"]).to eq md_user.id
      expect(response).to redirect_to "/"
    end

    it "login with both legacy and new session cookie ignores the legacy cookie" do
      new_md_user = UserFixture.signed_up.create(origin: "mysterydoug")

      cookies["_session_id"] = legacy_md_crypt.encrypt_session({session_id: session_id, current_user_id: md_user.id})
      cookies["_m_session_id"] = new_crypt.encrypt_session({session_id: session_id, current_user_id: new_md_user.id})
      headers = {"X-COOKIE-UPGRADER" => "true"}
      get "/log-in", params: {}, headers: headers
      cookie = response.cookies["_m_session_id"]
      decrypted_session = new_crypt.decrypt_session(cookie)
      expect(decrypted_session["current_user_id"]).to eq new_md_user.id
      expect(response).to redirect_to "/"
    end

    it "roundtrips an existing session" do
      cookies["_session_id"] = legacy_md_crypt.encrypt_session({session_id: session_id, current_user_id: md_user.id})
      get "/", params: {}, headers: {"X-COOKIE-UPGRADER" => "true"}
      cookie = response.cookies["_m_session_id"]
      expect(cookie).not_to be_nil
      decrypted_session = new_crypt.decrypt_session(cookie)
      expect(decrypted_session).not_to be_nil
      expect(decrypted_session.keys).to include("session_id", "current_user_id")
      expect(decrypted_session["session_id"]).to eq session_id
      expect(User.unscoped.exists?(decrypted_session["current_user_id"])).to be_truthy
      expect(decrypted_session["current_user_id"]).to eq md_user.id
    end

    it "roundtrips without existing session" do
      get "/", params: {}, headers: {"X-COOKIE-UPGRADER" => "true"}
      cookie = response.cookies["_m_session_id"]
      decrypted_session = new_crypt.decrypt_session(cookie)
      expect(decrypted_session).not_to be_nil
      expect(decrypted_session["session_id"]).not_to eq session_id
      expect(User.unscoped.exists?(decrypted_session["current_user_id"])).to be_truthy
      expect(decrypted_session["current_user_id"]).not_to eq md_user.id
    end

    it "requires a custom header for now" do
      # TODO: These tests are less important now, probably delete after we get this put to bed.
      #
      # Basically just showing we always expect to get the new session name out regardless.
      get "/"
      expect(response.cookies["_session_id"]).to be_nil
      expect(response.cookies["_m_session_id"]).not_to be_nil

      get "/", params: {}, headers: {"X-COOKIE-UPGRADER" => "true"}
      expect(response.cookies["_session_id"]).to be_nil
      expect(response.cookies["_m_session_id"]).not_to be_nil

      get "/"
      expect(response.cookies["_session_id"]).to be_nil
      expect(response.cookies["_m_session_id"]).not_to be_nil
    end
  end

  context "mysteryscience.com" do
    before do
      host! "mysteryscience.com"
    end

    it "juggles cookie settings for mysteryscience.com" do
      cookies["_session_id"] = legacy_ms_crypt.encrypt_session({session_id: session_id, current_user_id: ms_user.id})
      get "/", params: {}, headers: {"X-COOKIE-UPGRADER" => "true"}
      cookie = response.cookies["_m_session_id"]
      expect(cookie).not_to be_nil
      decrypted_session = new_crypt.decrypt_session(cookie)
      expect(decrypted_session).not_to be_nil
      expect(decrypted_session.keys).to eq %w(session_id current_user_id _csrf_token)
      expect(decrypted_session["session_id"]).to eq session_id
      expect(User.unscoped.exists?(decrypted_session["current_user_id"])).to be_truthy
      expect(decrypted_session["current_user_id"]).to eq ms_user.id
    end
  end

  context "CookieHeader" do
    context "#to_hash" do
      it "should keep multiple instances of the same name" do
        hash = CookieUpgrader::CookieHeader.to_hash("a=foo; b=bar, a=qux")
        expect(hash).to eq("a" => ["foo", "qux"], "b" => ["bar"])
      end
    end

    it "#to_string" do
      hash = {"a" => ["foo", "qux"], "b" => ["bar"]}
      string = CookieUpgrader::CookieHeader.to_string(hash)
      expect(string).to eq "a=foo; a=qux; b=bar"
    end
  end

  context "CookieSwapper" do
    let(:old_key) { "old_key" }
    let(:new_key) { "new_key" }
    let(:old_secret) { "old_secret" }
    let(:new_secret) { "new_secret" }
    let(:old_enc_config) { encrypt_config(old_secret) }
    let(:new_enc_config) { encrypt_config(new_secret) }
    let(:old_crypt) { CookieUpgrader::CookieEncryptor.new(old_enc_config) }
    let(:new_crypt) { CookieUpgrader::CookieEncryptor.new(new_enc_config) }
    let(:swapper) { CookieUpgrader::CookieSwapper.new(new_enc_config, new_key, new_secret) }

    it "should do nothing if new session cookie exists" do
      result = swapper.swap("#{new_key}=my_fake_cookie", old_key, old_secret, "foo.com")
      expect(result).to eq nil
    end

    it "should return if header is empty" do
      result = swapper.swap("", old_key, old_secret, "foo.com")
      expect(result).to eq nil
    end

    it "should upgrade the cookie" do
      old_encrypted_session = old_crypt.encrypt_session({a: 1})
      cookie_header = "#{old_key}=#{old_encrypted_session}"
      result = swapper.swap(cookie_header, old_key, old_secret, "foo.com")
      expect(result).to_not be_nil, "something wicked has occurred, check log output"

      key, encrypted = result.scan(/(#{new_key})=(.*)/).flatten
      expect(key).to eq new_key
      expect(new_crypt.decrypt_session(encrypted)).to eq({"a" => 1})
    end

    it "should react if bad data causes bad old decryption" do
      old_maligned_encryption = "#{old_crypt.encrypt_session({a: 1})}".reverse
      result = swapper.swap("#{old_key}=#{old_maligned_encryption}", old_key, old_secret, "foo.com")
      expect(result).to be_nil
    end
  end
end

def default_enc_config
  CookieUpgrader::EncryptionConfig.new.tap do |ec|
    ec.secret_key_base = Rails.application.secrets[:secret_key_base]
    ec.encrypted_cookie_salt = "encrypted cookie"
    ec.encrypted_signed_cookie_salt = "signed encrypted cookie"
    ec.cookies_serializer = :json
    ec.cookies_digest = nil
  end
end

def encrypt_config(secret_key_base)
  default_enc_config.dup.tap { |ec| ec.secret_key_base = secret_key_base }
end
