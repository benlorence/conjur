shared_context "authn setup" do
  let(:input) do
    ::Authentication::AuthenticatorInput.new(
      authenticator_name: 'authn',
      service_id:         'service',
      account:            'account',
      username:           'username',
      credentials:        'creds',
      client_ip:          '127.0.0.1',
      request:            nil
    )
  end

  let(:mocked_role) { double("Role") }
  def mocked_role
    double('Role').tap do |role|
      allow(role).to receive(:roleid_from_username)
                       .and_return("account:user:username")
    end
  end

  let(:mocked_credentials) { double("Credentials") }
  def mocked_credentials
    double('Credentials').tap do |creds|
      allow(creds).to receive(:[]).and_return(creds)
      allow(creds).to receive(:authenticate).and_return(true)
      allow(creds).to receive(:api_key).and_return('a valid api key')
    end
  end

  let(:mocked_role_not_found_credentials) { double("Credentials") }
  def mocked_role_not_found_credentials
    double('Credentials').tap do |creds|
      allow(creds).to receive(:[]).and_return(nil)
    end
  end


  let(:mocked_invalid_api_key_credentials) { double("Credentials") }
  def mocked_invalid_api_key_credentials
    double('Credentials').tap do |creds|
      allow(creds).to receive(:[]).and_return(creds)
      allow(creds).to receive(:valid_api_key?).and_return(false)
    end
  end

  let(:mocked_valid_api_key_credentials) { double("Credentials") }
  def mocked_valid_api_key_credentials
    double('Credentials').tap do |creds|
      allow(creds).to receive(:[]).and_return(creds)
      allow(creds).to receive(:valid_api_key?).and_return(true)
    end
  end
end
