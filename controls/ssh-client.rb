# My compliance profile for checking the SSH client config

title 'SSH Client'

control 'ssh-1' do
  impact 1.0
  title 'Client: Set SSH protocol version to 2'
  desc "
    Set the SSH protocol version to 2. Don't use legacy
    insecure SSHv1 connections anymore.
  "

  tag cis: 'CIS-6.2.1'
  tag my_corp: 'AUDIT-2015-4.7F'

  describe ssh_config do
    its('Protocol') { should eq('2') }
  end
end
