# My compliance profile for checking the SSH server config

title 'SSH Server'

control 'sshd-1' do
  impact 1.0
  title 'Server: Set protocol version to SSHv2'
  desc "
    Set the SSH protocol version to 2. Don't use legacy insecure SSHv1 connections anymore.
  "

  tag cis: 'CIS-6.2.1'
  tag my_corp: 'AUDIT-2015-4.7F'
  ref 'Corporate Requirements', url: 'https://corpweb/audit/'

  describe sshd_config do
    its('Protocol') { should eq('2') }
  end
end

control 'sshd-2' do
  impact 1.0
  title 'Server: Disable X11 forwarding'
  desc '
    Prevent X11 forwarding by default, as it can be used in a limited way to enable attacks.
  '

  tag cis: 'CIS-6.2.4'
  tag my_corp: 'AUDIT-2015-4.7G'
  ref 'Corporate Requirements', url: 'https://corpweb/audit/'

  describe sshd_config do
    its('X11Forwarding') { should eq('no') }
  end
end

control 'sshd-3' do
  impact 0.7
  title 'Server: MaxAuthTries should be 4 or less'
  desc '
    Limit SSH login attempts to 4 to mitigate brute force login attempts.
  '

  tag cis: 'CIS-6.2.5'
  tag my_corp: 'AUDIT-2015-4.7AQ'
  ref 'Corporate Requirements', url: 'https://corpweb/audit/'

  describe sshd_config do
    its('X11UseLocalhost') { should eq('yes') }
  end
end
