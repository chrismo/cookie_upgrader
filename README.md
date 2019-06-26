# CookieUpgrader

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cookie_upgrader'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install session_upgrader

## Usage

TODO: Write usage instructions here

```ruby
config.middleware.insert_before ActionDispatch::Cookies, CookieUpgrader,
                                YAML.safe_load(ERB.new(File.read(Rails.root.join("config", "cookie_upgrader.yml"))).result)[Rails.env]
```

production:
  domain.name:
    old_secret_key_base: <%= ENV['OLD_SECRET_KEY_BASE'] %>
    old_session_cookie_key: "_session_id"


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run
`rake spec` to run the tests. You can also run `bin/console` for an interactive
prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To
release a new version, update the version number in `version.rb`, and then run
`bundle exec rake release`, which will create a git tag for the version, push
git commits and tags, and push the `.gem` file to
[rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at
https://github.com/mysterysci/cookie_upgrader.

## License

The gem is available as open source under the terms of the [MIT
License](https://opensource.org/licenses/MIT).

## Other Options

- https://github.com/fac/hestia - MonkeyPunches into SignedJar, but I'm not sure
  that's always used in all cases.

- https://github.com/envato/rails_session_key_rotator - Works as middleware, but
  is it too simple? Will it work with Rails 4?
