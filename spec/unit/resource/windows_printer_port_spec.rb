#
# Copyright:: Copyright 2018, Chef Software, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require "spec_helper"

describe Chef::Resource::WindowsPrinterPort do
  let(:ipv4_address) { "63.192.209.236" }
  let(:resource) { Chef::Resource::WindowsPrinterPort.new(ipv4_address, run_context) }
  let(:shell_out_result) { double("shellout", stdout: nil, stderr: nil, exitstatus: nil) }

  let(:node) { Chef::Node.new }
  let(:events) { Chef::EventDispatch::Dispatcher.new }
  let(:run_context) { Chef::RunContext.new(node, {}, events) }

  error_getting_port_config = "Microsoft (R) Windows Script Host Version 5.8\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n\r\nUnable to get port Error 0x80041002 Not found \r\nOperation \r\nProvider Win32 Provider\r\nDescription The printer name is invalid. \r\n"
  port_config = "Microsoft (R) Windows Script Host Version 5.8\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n\r\n\r\nServer name \r\nPort name IP_10.4.64.38\r\nHost address 10.4.64.38\r\nProtocol RAW\r\nPort number 9100\r\nSNMP Disabled\r\n"

  before do
    allow_any_instance_of(described_class).to receive(:shell_out!).with("cscript.exe \"#{described_class::PRINTING_ADMIN_SCRIPTS_DIR}\\prnport.vbs\" -l").and_return(shell_out_result)
    allow_any_instance_of(described_class).to receive(:shell_out!).with("cscript.exe \"#{described_class::PRINTING_ADMIN_SCRIPTS_DIR}\\prnport.vbs\" -g -r \"#{resource.port_name}\"").and_return(shell_out_result)
  end

  it "sets resource name as :windows_printer_port" do
    expect(resource.resource_name).to eql(:windows_printer_port)
  end

  it "the ipv4_address property is the name_property" do
    expect(resource.ipv4_address).to eql(ipv4_address)
  end

  it 'port_name defaults to IP_#{ipv4_address}' do
    expect(resource.port_name).to eq("IP_#{ipv4_address}")
  end

  it "sets the default action as :create" do
    expect(resource.action).to eql([:create])
  end

  it "supports :create, :delete actions" do
    expect { resource.action :create }.not_to raise_error
    expect { resource.action :delete }.not_to raise_error
  end

  it "port_number property defaults to 9100" do
    expect(resource.port_number).to eql(9100)
  end

  it "snmp_enabled property defaults to false" do
    expect(resource.snmp_enabled).to eql(false)
  end

  it "port_protocol property defaults to :raw" do
    expect(resource.port_protocol).to eql(:raw)
  end

  it "port_protocol converts \"raw\" to :raw" do
    expect(resource.port_protocol "raw").to eq(:raw)
  end

  it "port_protocol converts \"lpr\" to :lpr" do
    expect(resource.port_protocol "lpr").to eq(:lpr)
  end

  it "port_protocol converts 1 to :raw" do
    expect(resource.port_protocol 1).to eq(:raw)
  end

  it "port_protocol converts 2 to :lpr" do
    expect(resource.port_protocol 2).to eq(:lpr)
  end

  it "raises an error if port_protocol isn't :raw or :lpr" do
    expect { resource.port_protocol :other }.to raise_error(ArgumentError)
    expect { resource.port_protocol 3 }.to raise_error(ArgumentError)
  end

  it "raises an error if ipv4_address isn't a valid IP Address" do
    expect { resource.ipv4_address "123.123.123.123" }.not_to raise_error
    expect { resource.ipv4_address "a.b.c.d" }.to raise_error(ArgumentError)
    expect { resource.ipv4_address "356.233.1.1" }.to raise_error(ArgumentError)
  end

  describe "#load_current_value!" do
    it 'is nil when current value does not exist' do
      provider = resource.provider_for_action(:create)
    end
  end

  describe '#port_names' do
    it 'returns a list of port names' do
      allow(shell_out_result).to receive(:stdout).and_return("Microsoft (R) Windows Script Host Version 5.8\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n\r\n\r\nServer name \r\nPort name random port name\r\nHost address 128.22.99.4\r\nProtocol RAW\r\nPort number 9100\r\nSNMP Disabled\r\n\r\nServer name \r\nPort name IP_10.4.64.38\r\nHost address 10.4.64.38\r\nProtocol RAW\r\nPort number 9100\r\nSNMP Disabled\r\n\r\nServer name \r\nPort name IP_10.55.1.3\r\nHost address 10.55.1.3\r\nProtocol RAW\r\nPort number 9100\r\nSNMP Disabled\r\n\r\nNumber of ports enumerated 2\r\n")
      expect(resource.port_names).to eq(['random port name', 'IP_10.4.64.38', 'IP_10.55.1.3'])

      allow(shell_out_result).to receive(:stdout).and_return("")
      expect(resource.port_names).to eq([])
    end
  end

  describe '#port_exists?' do
    it 'returns true if port exists' do
      allow(shell_out_result).to receive(:stdout).and_return("Microsoft (R) Windows Script Host Version 5.8\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n\r\n\r\nServer name \r\nPort name IP_#{ipv4_address}\r\nHost address #{ipv4_address}\r\nProtocol RAW\r\nPort number 9100\r\nSNMP Disabled\r\n\r\nNumber of ports enumerated 1\r\n")
      expect(resource.port_exists?).to be true
    end

    it 'returns false if port does not exist' do
      allow(shell_out_result).to receive(:stdout).and_return("Microsoft (R) Windows Script Host Version 5.8\r\nCopyright (C) Microsoft Corporation. All rights reserved.\r\n\r\n\r\nServer name \r\nPort name IP_10.4.64.38\r\nHost address 10.4.64.38\r\nProtocol RAW\r\nPort number 9100\r\nSNMP Disabled\r\n\r\nNumber of ports enumerated 1\r\n")
      expect(resource.port_exists?).to be false
    end
  end
end
