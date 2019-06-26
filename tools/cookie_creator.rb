module Tools
  module RaiseEncryptErrors
    # production method swallows exceptions
    def decrypt_and_verify(encrypted_message)
      @encryptor.decrypt_and_verify(encrypted_message)
    end
  end

  module CookieCreator
    def legacy_md_session_cookie(new_session_cookie)
      legacy_cookie = legacy_session_cookie(new_session_cookie, CookieUpgrader::CookieEncryptor.new(md_secret))
      puts '-' * 80
      puts "1) rename _m_session_id cookie to _session_id"
      puts "2) change the domain on the cookie from .mysterydoug.com to mysterydoug.com"
      puts "3) replace with these contents:"
      puts legacy_cookie
    end

    def legacy_ms_session_cookie(new_session_cookie)
      legacy_cookie = legacy_session_cookie(new_session_cookie, CookieUpgrader::CookieEncryptor.new(ms_secret))
      puts '-' * 80
      puts "rename _m_session_id cookie to _session_id and replace with these contents:"
      puts legacy_cookie
    end

    def upgrader_config
      YAML.safe_load(ERB.new(File.read(Rails.root.join("config", "cookie_upgrader.yml"))).result)[Rails.env]
    end

    def md_secret
      upgrader_config["mysterydoug.com"]["old_secret_key_base"]
    end

    def ms_secret
      upgrader_config["mysteryscience.com"]["old_secret_key_base"]
    end

    def legacy_session_cookie(new_session_cookie, elf)
      session_hash = new_encryptor.decrypt_session(unescape(new_session_cookie))
      puts "Decrypted session hash:"
      p session_hash
      elf.encrypt_session(session_hash)
    end

    def new_encryptor
      CookieUpgrader::CookieEncryptor.new(Rails.application.secrets.secret_key_base)
    end

    def unescape(value)
      value.gsub(/%3D/, "=")
    end

    def decrypt_legacy_ms_cookie(cookie)
      CookieUpgrader::CookieEncryptor.new(ms_secret).decrypt_session(unescape(cookie))
    end

    def decrypt_legacy_md_cookie(cookie)
      CookieUpgrader::CookieEncryptor.new(md_secret).decrypt_session(unescape(cookie))
    end

    def decrypt_new_cookie(cookie)
      new_encryptor.decrypt_session(unescape(cookie))
    end

    def raise_encryption_errors!
      ActionDispatch::Cookies::EncryptedCookieJar.prepend(RaiseEncryptErrors)
    end

    def decrypt_from_logs(paste)
      host_map = {
        "mysteryscience.com" => {"old" => :decrypt_legacy_ms_cookie, "new" => :decrypt_new_cookie},
        "mysterydoug.com" => {"old" => :decrypt_legacy_md_cookie, "new" => :decrypt_new_cookie}
      }
      lines = paste.split("\n")
      lines.each_with_index do |ln, idx|
        regexp = /(\S+?) (old|new) \| .*?_session_id=(\S+)/
        host, state, enc_cookie = ln.scan(regexp).flatten
        if state == "old"
          decrypted_old = send(host_map[host][state], enc_cookie.scan(/[A-Za-z0-9=-]+/).join)
          new_line = lines[idx + 1]
          next unless new_line
          host, state, enc_cookie = new_line.scan(regexp).flatten
          if state == "new"
            decrypted_new = send(host_map[host][state], enc_cookie.scan(/[A-Za-z0-9=-]+/).join)
            if decrypted_old == decrypted_new
              if decrypted_old.nil?
                puts "Both nil: #{decrypted_old.inspect} | #{decrypted_new.inspect}"
              else
                puts "MATCH!: #{decrypted_old.inspect} | #{decrypted_new.inspect}"
              end
            else
              puts "Nope: #{decrypted_old.inspect} | #{decrypted_new.inspect}"
            end
          end
        end
      end
    end
  end
end

