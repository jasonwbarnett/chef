#
# Author:: Nuo Yan <nuo@chef.io>
# Author:: Seth Chisamore <schisamo@chef.io>
# Copyright:: Copyright 2010-2016, Chef Software Inc.
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
require "mixlib/shellout"

class Chef::ReservedNames::Win32::Security; end

describe Chef::Provider::Service::Windows, "load_current_resource" do
  include_context "Win32"

  let(:new_resource) { Chef::Resource::WindowsService.new("chef") }
  let(:provider) do
    prvdr = Chef::Provider::Service::Windows.new(new_resource,
      Chef::RunContext.new(Chef::Node.new, {}, Chef::EventDispatch::Dispatcher.new))
    prvdr.current_resource = Chef::Resource::WindowsService.new("current-chef")
    prvdr
  end
  let(:service_right) { Chef::Provider::Service::Windows::SERVICE_RIGHT }

  before(:all) do
    Win32::Service = Class.new
  end

  before(:each) do
    Win32::Service::AUTO_START = 0x00000002
    Win32::Service::DEMAND_START = 0x00000003
    Win32::Service::DISABLED = 0x00000004

    allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
      double("StatusStruct", :current_state => "running"))
    allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
      double("Struct::ServiceConfigInfo",
        service_type: 'share process',
        start_type: 'auto start',
        error_control: 'normal',
        binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted',
        load_order_group: 'TDI',
        tag_id: 0,
        dependencies: %w(NSI Tdx Afd),
        service_start_name: 'NT Authority\\LocalService',
        display_name: 'DHCP Client'
      ))
    allow(Win32::Service).to receive(:services).and_return([
      double('Struct::ServiceInfo', service_name: 'ACPI', display_name: 'Microsoft ACPI Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\ACPI.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Core', tag_id: 2, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'acpiex', display_name: 'Microsoft ACPIEx Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\Drivers\\acpiex.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Boot Bus Extender', tag_id: 7, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'AFD', display_name: 'Ancillary Function Driver for Winsock', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\afd.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'PNP_TDI', tag_id: 0, start_name: '', dependencies: [], description: 'Ancillary Function Driver for Winsock', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'ahcache', display_name: 'Application Compatibility Cache', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\DRIVERS\\ahcache.sys', start_type: 'system start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'Cache Compatibility Data and Attributes for Individual PE File', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'BasicDisplay', display_name: 'BasicDisplay', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\BasicDisplay.sys', start_type: 'system start', error_control: 'ignore', load_order_group: 'Video', tag_id: 3, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'BasicRender', display_name: 'BasicRender', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\BasicRender.sys', start_type: 'system start', error_control: 'ignore', load_order_group: 'Video', tag_id: 2, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'BFE', display_name: 'Base Filtering Engine', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'power event'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetwork', start_type: 'auto start', error_control: 'normal', load_order_group: 'NetworkProvider', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: %w(RpcSs WfpLwfs), description: 'The Base Filtering Engine (BFE) is a service that manages firewall and Internet Protocol security (IPsec) policies and implements user mode filtering. Stopping or disabling the BFE service will significantly reduce the security of the system. It will also result in unpredictable behavior in IPsec management and firewall applications.', interactive: false, pid: 340, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'BITS', display_name: 'Background Intelligent Transfer Service', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RpcSs EventSystem), description: 'Transfers files in the background using idle network bandwidth. If the service is disabled, then any applications that depend on BITS, such as Windows Update or MSN Explorer, will be unable to automatically download programs and other information.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 120000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 1),
      double('Struct::ServiceInfo', service_name: 'bowser', display_name: 'Browser Support Driver', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\DRIVERS\\bowser.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Network', tag_id: 5, start_name: '', dependencies: [], description: 'Implements the kernel datagram receiver for the computer browser browser service.', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'BrokerInfrastructure', display_name: 'Background Tasks Infrastructure Service', service_type: 'share process', current_state: 'running', controls_accepted: ['session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch', start_type: 'auto start', error_control: 'normal', load_order_group: 'COM Infrastructure', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RpcEptMapper DcomLaunch RpcSs), description: 'Windows infrastructure service that controls which background tasks can run on the system.', interactive: false, pid: 552, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'reboot', delay: 120000 }, 2 => { action_type: 'reboot', delay: 120000 }, 3 => { action_type: 'reboot', delay: 120000 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'cdrom', display_name: 'CD-ROM Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\cdrom.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'SCSI CDROM Class', tag_id: 3, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'CLFS', display_name: 'Common Log (CLFS)', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\CLFS.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Filter', tag_id: 1, start_name: '', dependencies: [], description: 'General-purpose logging service', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'CmBatt', display_name: 'Microsoft ACPI Control Method Battery Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\CmBatt.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'CNG', display_name: 'CNG', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\Drivers\\cng.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Core', tag_id: 4, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'CompositeBus', display_name: 'Composite Bus Enumerator Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\CompositeBus.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Extended Base', tag_id: 23, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'condrv', display_name: 'Console Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\drivers\\condrv.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Base', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'CryptSvc', display_name: 'Cryptographic Services', service_type: 'share process', current_state: 'running', controls_accepted: ['shutdown', 'stop', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k NetworkService', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT Authority\\NetworkService', dependencies: ['RpcSs'], description: 'Provides three management services: Catalog Database Service, which confirms the signatures of Windows files and allows new programs to be installed; Protected Root Service, which adds and removes Trusted Root Certification Authority certificates from this computer; and Automatic Root Certificate Update Service, which retrieves root certificates from Windows Update and enable scenarios such as SSL. If this service is stopped, these management services will not function properly. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 932, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'none', delay: 0 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'DcomLaunch', display_name: 'DCOM Server Process Launcher', service_type: 'share process', current_state: 'running', controls_accepted: ['session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch', start_type: 'auto start', error_control: 'normal', load_order_group: 'COM Infrastructure', tag_id: 0, start_name: 'LocalSystem', dependencies: [], description: 'The DCOMLAUNCH service launches COM and DCOM servers in response to object activation requests. If this service is stopped or disabled, programs using COM or DCOM will not function properly. It is strongly recommended that you have the DCOMLAUNCH service running.', interactive: false, pid: 552, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 1, actions: { 1 => { action_type: 'reboot', delay: 60000 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Dfsc', display_name: 'DFS Namespace Client Driver', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\Drivers\\dfsc.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'Network', tag_id: 0, start_name: '', dependencies: ['Mup'], description: 'Client driver for access to DFS Namespaces', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Dhcp', display_name: 'DHCP Client', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted', start_type: 'auto start', error_control: 'normal', load_order_group: 'TDI', tag_id: 0, start_name: 'NT Authority\\LocalService', dependencies: %w(NSI Tdx Afd), description: 'Registers and updates IP addresses and DNS records for this computer. If this service is stopped, this computer will not receive dynamic IP addresses and DNS updates. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 780, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'disk', display_name: 'Disk Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\disk.sys', start_type: 'boot start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Dnscache', display_name: 'DNS Client', service_type: 'share process', current_state: 'running', controls_accepted: ['netbind change', 'param change', 'stop', 'power event'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k NetworkService', start_type: 'auto start', error_control: 'normal', load_order_group: 'TDI', tag_id: 0, start_name: 'NT AUTHORITY\\NetworkService', dependencies: %w(Tdx nsi), description: "The DNS Client service (dnscache) caches Domain Name System (DNS) names and registers the full computer name for this computer. If the service is stopped, DNS names will continue to be resolved. However, the results of DNS name queries will not be cached and the computer's name will not be registered. If the service is disabled, any services that explicitly depend on it will fail to start.", interactive: false, pid: 932, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'DPS', display_name: 'Diagnostic Policy Service', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k LocalServiceNoNetwork', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: [], description: 'The Diagnostic Policy Service enables problem detection, troubleshooting and resolution for Windows components.  If this service is stopped, diagnostics will no longer function.', interactive: false, pid: 340, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 1),
      double('Struct::ServiceInfo', service_name: 'DsmSvc', display_name: 'Device Setup Manager', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RpcSs HTTP), description: 'Enables the detection, download and installation of device-related software. If this service is disabled, devices may be configured with outdated software, and may not work correctly.', interactive: false, pid: 812, service_flags: 0, reset_period: 3600, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 120000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'DXGKrnl', display_name: 'LDDM Graphics Subsystem', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\dxgkrnl.sys', start_type: 'demand start', error_control: 'ignore', load_order_group: 'Video Init', tag_id: 1, start_name: '', dependencies: [], description: 'Controls the underlying video driver stacks to provide fully-featured display capabilities.', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'E1G60', display_name: 'Intel(R) PRO/1000 NDIS 6 Adapter Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\E1G6032E.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'NDIS', tag_id: 23, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'EventLog', display_name: 'Windows Event Log', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k LocalServiceNetworkRestricted', start_type: 'auto start', error_control: 'normal', load_order_group: 'Event Log', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: [], description: 'This service manages events and event logs. It supports logging events, querying events, subscribing to events, archiving event logs, and managing event metadata. It can display events in both XML and plain text format. Stopping this service may compromise security and reliability of the system.', interactive: false, pid: 780, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 120000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'EventSystem', display_name: 'COM+ Event System', service_type: 'share process', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalService', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: ['rpcss'], description: 'Supports System Event Notification Service (SENS), which provides automatic distribution of events to subscribing Component Object Model (COM) components. If the service is stopped, SENS will close and will not be able to provide logon and logoff notifications. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 844, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 1000 }, 2 => { action_type: 'restart', delay: 5000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'FltMgr', display_name: 'FltMgr', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\fltmgr.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'FSFilter Infrastructure', tag_id: 1, start_name: '', dependencies: [], description: 'File System Filter Manager Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'FontCache', display_name: 'Windows Font Cache Service', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalService', start_type: 'auto start', error_control: 'normal', load_order_group: 'AudioGroup', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: [], description: 'Optimizes performance of applications by caching commonly used font data. Applications will start this service if it is not already running. It can be disabled, though doing so will degrade application performance.', interactive: false, pid: 844, service_flags: 0, reset_period: 300, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 120000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'gpsvc', display_name: 'Group Policy Client', service_type: 'share process', current_state: 'running', controls_accepted: ['pre-shutdown', 'stop', 'power event'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'normal', load_order_group: 'ProfSvc_Group', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RPCSS Mup), description: 'The service is responsible for applying settings configured by administrators for the computer and users through the Group Policy component. If the service is disabled, the settings will not be applied and applications and components will not be manageable through Group Policy. Any components or applications that depend on the Group Policy component might not be functional if the service is disabled.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'HdAudAddService', display_name: 'Microsoft 1.1 UAA Function Driver for High Definition Audio Service', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\HdAudio.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'HDAudBus', display_name: 'Microsoft UAA Bus Driver for High Definition Audio', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\HDAudBus.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Extended Base', tag_id: 29, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'HidUsb', display_name: 'Microsoft HID Class Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\hidusb.sys', start_type: 'demand start', error_control: 'ignore', load_order_group: 'extended base', tag_id: 16, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'HTTP', display_name: 'HTTP Service', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\drivers\\HTTP.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'HTTP Service', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'i8042prt', display_name: 'i8042 Keyboard and PS/2 Mouse Port Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\i8042prt.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Keyboard Port', tag_id: 5, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'intelppm', display_name: 'Intel Processor Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\intelppm.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Extended Base', tag_id: 13, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'iphlpsvc', display_name: 'IP Helper', service_type: 'share process', current_state: 'running', controls_accepted: ['param change', 'stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k NetSvcs', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RpcSS Tdx winmgmt tcpip nsi WinHttpAutoProxySvc), description: 'Provides tunnel connectivity using IPv6 transition technologies (6to4, ISATAP, Port Proxy, and Teredo), and IP-HTTPS. If this service is stopped, the computer will not have the enhanced connectivity benefits that these technologies offer.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'kbdclass', display_name: 'Keyboard Class Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\kbdclass.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'kdnic', display_name: 'Microsoft Kernel Debug Network Miniport (NDIS 6.20)', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\kdnic.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'NDIS', tag_id: 22, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'KSecDD', display_name: 'KSecDD', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\Drivers\\ksecdd.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Base', tag_id: 1, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'KSecPkg', display_name: 'KSecPkg', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\Drivers\\ksecpkg.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Cryptography', tag_id: 2, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'ksthunk', display_name: 'Kernel Streaming Thunks', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\ksthunk.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'PNP Filter', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'LanmanServer', display_name: 'Server', service_type: 'share process', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(SamSS Srv2), description: 'Supports file, print, and named-pipe sharing over the network for this computer. If this service is stopped, these functions will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 120000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'LanmanWorkstation', display_name: 'Workstation', service_type: 'share process', current_state: 'running', controls_accepted: ['pause continue', 'stop', 'power event'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k NetworkService', start_type: 'auto start', error_control: 'normal', load_order_group: 'NetworkProvider', tag_id: 0, start_name: 'NT AUTHORITY\\NetworkService', dependencies: %w(Bowser MRxSmb20 NSI), description: 'Creates and maintains client network connections to remote servers using the SMB protocol. If this service is stopped, these connections will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 932, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 120000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'lltdio', display_name: 'Link-Layer Topology Discovery Mapper I/O Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\lltdio.sys', start_type: 'auto start', error_control: 'normal', load_order_group: 'NDIS', tag_id: 17, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'lmhosts', display_name: 'TCP/IP NetBIOS Helper', service_type: 'share process', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted', start_type: 'auto start', error_control: 'normal', load_order_group: 'TDI', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: %w(NetBT Afd), description: 'Provides support for the NetBIOS over TCP/IP (NetBT) service and NetBIOS name resolution for clients on the network, therefore enabling users to share files, print, and log on to the network. If this service is stopped, these functions might be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 780, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 100 }, 2 => { action_type: 'restart', delay: 100 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'LSM', display_name: 'Local Session Manager', service_type: 'share process', current_state: 'running', controls_accepted: [], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch', start_type: 'auto start', error_control: 'normal', load_order_group: 'COM Infrastructure', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RpcEptMapper DcomLaunch RpcSs), description: 'Core Windows Service that manages local user sessions. Stopping or disabling this service will result in system instability.', interactive: false, pid: 552, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'luafv', display_name: 'UAC File Virtualization', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\luafv.sys', start_type: 'auto start', error_control: 'normal', load_order_group: 'FSFilter Virtualization', tag_id: 0, start_name: '', dependencies: ['FltMgr'], description: 'Virtualizes file write failures to per-user locations.', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'monitor', display_name: 'Microsoft Monitor Class Function Driver Service', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\monitor.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mouclass', display_name: 'Mouse Class Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\mouclass.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mouhid', display_name: 'Mouse HID Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\mouhid.sys', start_type: 'demand start', error_control: 'ignore', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mountmgr', display_name: 'Mount Point Manager', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\mountmgr.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'System Bus Extender', tag_id: 0, start_name: '', dependencies: [], description: 'Driver responsible with maintaining persistent drive letters and names for volumes', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mpsdrv', display_name: 'Windows Firewall Authorization Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\drivers\\mpsdrv.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'network', tag_id: 0, start_name: '', dependencies: [], description: 'Windows Firewall Authorization Driver is a kernel mode driver that provides deep inspection services on inbound and outbound network traffic.', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'MpsSvc', display_name: 'Windows Firewall', service_type: 'share process', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNoNetwork', start_type: 'auto start', error_control: 'normal', load_order_group: 'NetworkProvider', tag_id: 0, start_name: 'NT Authority\\LocalService', dependencies: %w(mpsdrv bfe), description: 'Windows Firewall helps protect your computer by preventing unauthorized users from gaining access to your computer through the Internet or a network.', interactive: false, pid: 340, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mrxsmb', display_name: 'SMB MiniRedirector Wrapper and Engine', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\DRIVERS\\mrxsmb.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Network', tag_id: 5, start_name: '', dependencies: ['rdbss'], description: 'Implements the framework for the SMB filesystem redirector', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mrxsmb10', display_name: 'SMB 1.x MiniRedirector', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\DRIVERS\\mrxsmb10.sys', start_type: 'auto start', error_control: 'normal', load_order_group: 'Network', tag_id: 6, start_name: '', dependencies: ['mrxsmb'], description: 'Implements the SMB 1.x (CIFS) protocol. This protocol provides connectivity to network resources on pre-Windows Vista servers', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mrxsmb20', display_name: 'SMB 2.0 MiniRedirector', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\DRIVERS\\mrxsmb20.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Network', tag_id: 7, start_name: '', dependencies: ['mrxsmb'], description: 'Implements the SMB 2.0 protocol, which provides connectivity to network resources on Windows Vista and later servers', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'MSDTC', display_name: 'Distributed Transaction Coordinator', service_type: 'own process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\msdtc.exe', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\NetworkService', dependencies: %w(RPCSS SamSS), description: 'Coordinates transactions that span multiple resource managers, such as databases, message queues, and file systems. If this service is stopped, these transactions will fail. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 2612, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 1000 }, 2 => { action_type: 'restart', delay: 11000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 1),
      double('Struct::ServiceInfo', service_name: 'Msfs', display_name: 'Msfs', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '', start_type: 'system start', error_control: 'normal', load_order_group: 'File system', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'msisadrv', display_name: 'msisadrv', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\msisadrv.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Boot Bus Extender', tag_id: 2, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'mssmbios', display_name: 'Microsoft System Management BIOS Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\mssmbios.sys', start_type: 'system start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Mup', display_name: 'Mup', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\Drivers\\mup.sys', start_type: 'boot start', error_control: 'normal', load_order_group: 'Network', tag_id: 0, start_name: '', dependencies: [], description: 'Multiple UNC Provider Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NDIS', display_name: 'NDIS System Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\ndis.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'NDIS Wrapper', tag_id: 0, start_name: '', dependencies: [], description: 'NDIS System Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NdisTapi', display_name: 'Remote Access NDIS TAPI Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\ndistapi.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'Remote Access NDIS TAPI Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NdisVirtualBus', display_name: 'Microsoft Virtual Network Adapter Enumerator', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\NdisVirtualBus.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Extended Base', tag_id: 26, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NdisWan', display_name: 'Remote Access NDIS WAN Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\ndiswan.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'Remote Access NDIS WAN Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NDProxy', display_name: 'NDIS Proxy', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '', start_type: 'demand start', error_control: 'normal', load_order_group: 'PNP_TDI', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NetBIOS', display_name: 'NetBIOS Interface', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\DRIVERS\\netbios.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'NetBIOSGroup', tag_id: 2, start_name: '', dependencies: [], description: 'NetBIOS Interface', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NetBT', display_name: 'NetBT', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\DRIVERS\\netbt.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'PNP_TDI', tag_id: 0, start_name: '', dependencies: %w(Tdx tcpip), description: 'This service implements NetBios over TCP/IP.', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'netprofm', display_name: 'Network List Service', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k LocalService', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: %w(RpcSs nlasvc), description: 'Identifies the networks to which the computer has connected, collects and stores properties for these networks, and notifies applications when these properties change.', interactive: false, pid: 844, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 100 }, 2 => { action_type: 'restart', delay: 100 }, 3 => { action_type: 'none', delay: 100 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'NlaSvc', display_name: 'Network Location Awareness', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k NetworkService', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\NetworkService', dependencies: %w(NSI RpcSs TcpIp Dhcp Eventlog), description: 'Collects and stores configuration information for the network and notifies programs when this information is modified. If this service is stopped, configuration information might be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 932, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 100 }, 2 => { action_type: 'restart', delay: 100 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Npfs', display_name: 'Npfs', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '', start_type: 'system start', error_control: 'normal', load_order_group: 'File system', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'npsvctrig', display_name: 'Named pipe service trigger provider', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\npsvctrig.sys', start_type: 'system start', error_control: 'severe', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'nsi', display_name: 'Network Store Interface Service', service_type: 'share process', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalService', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT Authority\\LocalService', dependencies: %w(rpcss nsiproxy), description: 'This service delivers network notifications (e.g. interface addition/deleting etc) to user mode clients. Stopping this service will cause loss of network connectivity. If this service is disabled, any other services that explicitly depend on this service will fail to start.', interactive: false, pid: 844, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'nsiproxy', display_name: 'NSI Proxy Service Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\drivers\\nsiproxy.sys', start_type: 'system start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'NSI Proxy Service', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Ntfs', display_name: 'Ntfs', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '', start_type: 'demand start', error_control: 'normal', load_order_group: 'Boot File System', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Null', display_name: 'Null', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '', start_type: 'system start', error_control: 'normal', load_order_group: 'Base', tag_id: 1, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'partmgr', display_name: 'Partition Manager', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\partmgr.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Boot Bus Extender', tag_id: 0, start_name: '', dependencies: [], description: 'Disk class filter driver that auctions out partitions to volume managers', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'pci', display_name: 'PCI Bus Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\pci.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Boot Bus Extender', tag_id: 3, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'pcw', display_name: 'Performance Counters for Windows Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\pcw.sys', start_type: 'boot start', error_control: 'normal', load_order_group: 'Base', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'pdc', display_name: 'pdc', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\pdc.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Boot Bus Extender', tag_id: 0, start_name: '', dependencies: [], description: 'Power Dependency Coordinator Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'PEAUTH', display_name: 'PEAUTH', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\drivers\\peauth.sys', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'PlugPlay', display_name: 'Plug and Play', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch', start_type: 'demand start', error_control: 'normal', load_order_group: 'PlugPlay', tag_id: 0, start_name: 'LocalSystem', dependencies: [], description: 'Enables a computer to recognize and adapt to hardware changes with little or no user input. Stopping or disabling this service will result in system instability.', interactive: false, pid: 552, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 1, actions: { 1 => { action_type: 'restart', delay: 15000 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'PolicyAgent', display_name: 'IPsec Policy Agent', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k NetworkServiceNetworkRestricted', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT Authority\\NetworkService', dependencies: %w(Tcpip bfe), description: 'Internet Protocol security (IPsec) supports network-level peer authentication, data origin authentication, data integrity, data confidentiality (encryption), and replay protection.  This service enforces IPsec policies created through the IP Security Policies snap-in or the command-line tool "netsh ipsec".  If you stop this service, you may experience network connectivity issues if your policy requires that connections use IPsec.  Also,remote management of Windows Firewall is not available when this service is stopped.', interactive: false, pid: 1380, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Power', display_name: 'Power', service_type: 'share process', current_state: 'running', controls_accepted: [], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch', start_type: 'auto start', error_control: 'normal', load_order_group: 'Plugplay', tag_id: 0, start_name: 'LocalSystem', dependencies: [], description: 'Manages power policy and power policy notification delivery.', interactive: false, pid: 552, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'reboot', delay: 60000 }, 2 => { action_type: 'reboot', delay: 60000 }, 3 => { action_type: 'reboot', delay: 60000 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'PptpMiniport', display_name: 'WAN Miniport (PPTP)', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\raspptp.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'WAN Miniport (PPTP)', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'ProfSvc', display_name: 'User Profile Service', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'normal', load_order_group: 'profsvc_group', tag_id: 0, start_name: 'LocalSystem', dependencies: ['RpcSs'], description: "This service is responsible for loading and unloading user profiles. If this service is stopped or disabled, users will no longer be able to successfully sign in or sign out, apps might have problems getting to users' data, and components registered to receive profile event notifications won't receive them.", interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Psched', display_name: 'QoS Packet Scheduler', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\pacer.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'NDIS', tag_id: 14, start_name: '', dependencies: [], description: 'QoS Packet Scheduler', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'RasAgileVpn', display_name: 'WAN Miniport (IKEv2)', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\AgileVpn.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'WAN Miniport (IKEv2)', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Rasl2tp', display_name: 'WAN Miniport (L2TP)', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\rasl2tp.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'WAN Miniport (L2TP)', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'RasPppoe', display_name: 'Remote Access PPPOE Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\raspppoe.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'Remote Access PPPOE Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'RasSstp', display_name: 'WAN Miniport (SSTP)', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\rassstp.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'WAN Miniport (SSTP)', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'rdbss', display_name: 'Redirected Buffering Sub System', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'system32\\DRIVERS\\rdbss.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'Network', tag_id: 4, start_name: '', dependencies: ['Mup'], description: 'Provides the framework for network mini-redirectors', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'rdpbus', display_name: 'Remote Desktop Device Redirector Bus Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\rdpbus.sys', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'RpcEptMapper', display_name: 'RPC Endpoint Mapper', service_type: 'share process', current_state: 'running', controls_accepted: [], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k RPCSS', start_type: 'auto start', error_control: 'normal', load_order_group: 'COM Infrastructure', tag_id: 0, start_name: 'NT AUTHORITY\\NetworkService', dependencies: [], description: 'Resolves RPC interfaces identifiers to transport endpoints. If this service is stopped or disabled, programs using Remote Procedure Call (RPC) services will not function properly.', interactive: false, pid: 596, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'RpcSs', display_name: 'Remote Procedure Call (RPC)', service_type: 'share process', current_state: 'running', controls_accepted: ['power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k rpcss', start_type: 'auto start', error_control: 'normal', load_order_group: 'COM Infrastructure', tag_id: 0, start_name: 'NT AUTHORITY\\NetworkService', dependencies: %w(RpcEptMapper DcomLaunch), description: 'The RPCSS service is the Service Control Manager for COM and DCOM servers. It performs object activations requests, object exporter resolutions and distributed garbage collection for COM and DCOM servers. If this service is stopped or disabled, programs using COM or DCOM will not function properly. It is strongly recommended that you have the RPCSS service running.', interactive: false, pid: 596, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 1, actions: { 1 => { action_type: 'reboot', delay: 60000 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'rspndr', display_name: 'Link-Layer Topology Discovery Responder', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\rspndr.sys', start_type: 'auto start', error_control: 'normal', load_order_group: 'NDIS', tag_id: 16, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'SamSs', display_name: 'Security Accounts Manager', service_type: 'share process', current_state: 'running', controls_accepted: [], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\lsass.exe', start_type: 'auto start', error_control: 'normal', load_order_group: 'MS_WindowsLocalValidation', tag_id: 0, start_name: 'LocalSystem', dependencies: ['RPCSS'], description: 'The startup of this service signals other services that the Security Accounts Manager (SAM) is ready to accept requests.  Disabling this service will prevent other services in the system from being notified when the SAM is ready, which may in turn cause those services to fail to start correctly. This service should not be disabled.', interactive: false, pid: 492, service_flags: 1, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Schedule', display_name: 'Task Scheduler', service_type: 'share process', current_state: 'running', controls_accepted: ['shutdown', 'stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'normal', load_order_group: 'SchedulerGroup', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RPCSS SystemEventsBroker), description: 'Enables a user to configure and schedule automated tasks on this computer. The service also hosts multiple Windows system-critical tasks. If this service is stopped or disabled, these tasks will not be run at their scheduled times. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 60000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'secdrv', display_name: 'Security Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'SENS', display_name: 'System Event Notification Service', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'power event'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'normal', load_order_group: 'ProfSvc_Group', tag_id: 0, start_name: 'LocalSystem', dependencies: ['EventSystem'], description: 'Monitors system events and notifies subscribers to COM+ Event System of these events.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'ShellHWDetection', display_name: 'Shell Hardware Detection', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'ignore', load_order_group: 'ShellSvcGroup', tag_id: 0, start_name: 'LocalSystem', dependencies: ['RpcSs'], description: 'Provides notifications for AutoPlay hardware events.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 60000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'spaceport', display_name: 'Storage Spaces Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\spaceport.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'System Bus Extender', tag_id: 8, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Spooler', display_name: 'Print Spooler', service_type: 'own process, interactive', current_state: 'running', controls_accepted: ['stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\spoolsv.exe', start_type: 'auto start', error_control: 'normal', load_order_group: 'SpoolerGroup', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RPCSS http), description: "This service spools print jobs and handles interaction with the printer.  If you turn off this service, you won\x92t be able to print or see your printers.", interactive: true, pid: 1008, service_flags: 0, reset_period: 3600, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 5000 }, 2 => { action_type: 'restart', delay: 5000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'srv', display_name: 'Server SMB 1.xxx Driver', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\DRIVERS\\srv.sys', start_type: 'auto start', error_control: 'normal', load_order_group: 'Network', tag_id: 0, start_name: '', dependencies: ['srv2'], description: 'Enables connectivity from Windows XP and earlier clients', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'srv2', display_name: 'Server SMB 2.xxx Driver', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\DRIVERS\\srv2.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Network', tag_id: 0, start_name: '', dependencies: ['srvnet'], description: 'Enables connectivity from Windows Vista and later clients', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'srvnet', display_name: 'srvnet', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\DRIVERS\\srvnet.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Network', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'storahci', display_name: 'Microsoft Standard SATA AHCI Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\storahci.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'SCSI Miniport', tag_id: 65, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'swenum', display_name: 'Software Bus Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\swenum.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Extended Base', tag_id: 21, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'SystemEventsBroker', display_name: 'System Events Broker', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: %w(RpcEptMapper RpcSs), description: 'Coordinates execution of background work for WinRT application. If this service is stopped or disabled, then background work might not be triggered.', interactive: false, pid: 552, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'reboot', delay: 120000 }, 2 => { action_type: 'reboot', delay: 120000 }, 3 => { action_type: 'reboot', delay: 120000 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Tcpip', display_name: 'TCP/IP Protocol Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\tcpip.sys', start_type: 'boot start', error_control: 'normal', load_order_group: 'PNP_TDI', tag_id: 3, start_name: '', dependencies: [], description: 'TCP/IP Protocol Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'tcpipreg', display_name: 'TCP/IP Registry Compatibility', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'System32\\drivers\\tcpipreg.sys', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: ['tcpip'], description: 'Provides compatibility for legacy applications which interact with TCP/IP through the registry. If this service is stopped, certain applications may have impaired functionality.', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'tdx', display_name: 'NetIO Legacy TDI Support Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\tdx.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'PNP_TDI', tag_id: 4, start_name: '', dependencies: ['Tcpip'], description: 'NetIO Legacy TDI Support Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Themes', display_name: 'Themes', service_type: 'share process', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'normal', load_order_group: 'ProfSvc_Group', tag_id: 0, start_name: 'LocalSystem', dependencies: [], description: 'Provides user experience theme management.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 60000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'TrkWks', display_name: 'Distributed Link Tracking Client', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k LocalSystemNetworkRestricted', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: ['RpcSs'], description: 'Maintains links between NTFS files within a computer or across computers in a network.', interactive: false, pid: 1056, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'tunnel', display_name: 'Microsoft Tunnel Miniport Adapter Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\tunnel.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'NDIS', tag_id: 24, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'UALSVC', display_name: 'User Access Logging Service', service_type: 'share process', current_state: 'running', controls_accepted: ['pre-shutdown', 'stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalSystemNetworkRestricted', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: ['WinMgmt'], description: 'This service logs unique client access requests, in the form of IP addresses and user names, of installed products and roles on the local server. This information can be queried, via Powershell, by administrators needing to quantify client demand of server software for offline Client Access License (CAL) management. If the service is disabled, client requests will not be logged and will not be retrievable via Powershell queries. Stopping the service will not affect query of historical data (see supporting documentation for steps to delete historical data). The local system administrator must consult his, or her, Windows Server license terms to determine the number of CALs that are required for the server software to be appropriately licensed; use of the UAL service and data does not alter this obligation.', interactive: false, pid: 1056, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 1),
      double('Struct::ServiceInfo', service_name: 'umbus', display_name: 'UMBus Enumerator Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\umbus.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Extended Base', tag_id: 17, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'usbhub', display_name: 'Microsoft USB Standard Hub Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\usbhub.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Base', tag_id: 18, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'usbohci', display_name: 'Microsoft USB Open Host Controller Miniport Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\usbohci.sys', start_type: 'demand start', error_control: 'normal', load_order_group: 'Base', tag_id: 19, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'VBoxGuest', display_name: 'VirtualBox Guest Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\VBoxGuest.sys', start_type: 'boot start', error_control: 'normal', load_order_group: 'Base', tag_id: 25, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'VBoxMouse', display_name: 'VirtualBox Guest Mouse Service', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\VBoxMouse.sys', start_type: 'demand start', error_control: 'ignore', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'VBoxService', display_name: 'VirtualBox Guest Additions Service', service_type: 'own process', current_state: 'running', controls_accepted: ['shutdown', 'stop', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\VBoxService.exe', start_type: 'auto start', error_control: 'normal', load_order_group: 'Base', tag_id: 26, start_name: 'LocalSystem', dependencies: [], description: 'Manages VM runtime information, time synchronization, remote sysprep execution and miscellaneous utilities for guest operating systems.', interactive: false, pid: 700, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'VBoxSF', display_name: 'VirtualBox Shared Folders', service_type: 'file system driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\VBoxSF.sys', start_type: 'system start', error_control: 'normal', load_order_group: 'NetworkProvider', tag_id: 1, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'VBoxVideoW8', display_name: 'VBoxVideoW8', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\VBoxVideoW8.sys', start_type: 'demand start', error_control: 'ignore', load_order_group: 'Video', tag_id: 6, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'vdrvroot', display_name: 'Microsoft Virtual Drive Enumerator', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\vdrvroot.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'Boot Bus Extender', tag_id: 11, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'volmgr', display_name: 'Volume Manager Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\volmgr.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'System Bus Extender', tag_id: 9, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'volmgrx', display_name: 'Dynamic Volume Manager', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\volmgrx.sys', start_type: 'boot start', error_control: 'critical', load_order_group: 'System Bus Extender', tag_id: 10, start_name: '', dependencies: [], description: 'Extension of the volume manager driver that manages software RAID volumes (spanned, striped, mirrored, RAID-5) on dynamic disks', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'volsnap', display_name: 'Storage volumes', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\System32\\drivers\\volsnap.sys', start_type: 'boot start', error_control: 'critical', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'W32Time', display_name: 'Windows Time', service_type: 'share process', current_state: 'running', controls_accepted: ['netbind change', 'param change', 'shutdown', 'stop', 'hardware profile change', 'power event'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalService', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: [], description: 'Maintains date and time synchronization on all clients and servers in the network. If this service is stopped, date and time synchronization will be unavailable. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 844, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 60000 }, 2 => { action_type: 'restart', delay: 120000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Wanarpv6', display_name: 'Remote Access IPv6 ARP Driver', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\wanarp.sys', start_type: 'system start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: '', dependencies: [], description: 'Remote Access IPv6 ARP Driver', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Wcmsvc', display_name: 'Windows Connection Manager', service_type: 'share process', current_state: 'running', controls_accepted: ['shutdown', 'stop', 'power event', 'session change'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted', start_type: 'auto start', error_control: 'normal', load_order_group: 'TDI', tag_id: 0, start_name: 'NT Authority\\LocalService', dependencies: ['RpcSs'], description: 'Makes automatic connect/disconnect decisions based on the network connectivity options currently available to the PC and enables management of network connectivity based on Group Policy settings.', interactive: false, pid: 780, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Wdf01000', display_name: 'Kernel Mode Driver Frameworks service', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\drivers\\Wdf01000.sys', start_type: 'boot start', error_control: 'normal', load_order_group: 'WdfLoadGroup', tag_id: 0, start_name: '', dependencies: [], description: '', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'WFPLWFS', display_name: 'Microsoft Windows Filtering Platform', service_type: 'kernel driver', current_state: 'running', controls_accepted: ['stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: '\\SystemRoot\\system32\\DRIVERS\\wfplwfs.sys', start_type: 'boot start', error_control: 'normal', load_order_group: 'NDIS', tag_id: 20, start_name: '', dependencies: [], description: 'Microsoft Windows Filtering Platform', interactive: false, pid: 0, service_flags: 0, reset_period: 0, reboot_message: nil, command: nil, num_actions: 0, actions: nil, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'WinHttpAutoProxySvc', display_name: 'WinHTTP Web Proxy Auto-Discovery Service', service_type: 'share process', current_state: 'running', controls_accepted: ['stop', 'power event'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalService', start_type: 'demand start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\LocalService', dependencies: ['Dhcp'], description: 'WinHTTP implements the client HTTP stack and provides developers with a Win32 API and COM Automation component for sending HTTP requests and receiving responses. In addition, WinHTTP provides support for auto-discovering a proxy configuration via its implementation of the Web Proxy Auto-Discovery (WPAD) protocol.', interactive: false, pid: 844, service_flags: 0, reset_period: 86400000, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 0 }, 2 => { action_type: 'none', delay: 0 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'Winmgmt', display_name: 'Windows Management Instrumentation', service_type: 'share process', current_state: 'running', controls_accepted: ['pause continue', 'shutdown', 'stop'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k netsvcs', start_type: 'auto start', error_control: 'ignore', load_order_group: '', tag_id: 0, start_name: 'localSystem', dependencies: ['RPCSS'], description: 'Provides a common interface and object model to access management information about operating system, devices, applications and services. If this service is stopped, most Windows-based software will not function properly. If this service is disabled, any services that explicitly depend on it will fail to start.', interactive: false, pid: 812, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'WinRM', display_name: 'Windows Remote Management (WS-Management)', service_type: 'share process', current_state: 'running', controls_accepted: %w(shutdown stop), win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\System32\\svchost.exe -k NetworkService', start_type: 'auto start', error_control: 'normal', load_order_group: '', tag_id: 0, start_name: 'NT AUTHORITY\\NetworkService', dependencies: %w(RPCSS HTTP), description: 'Windows Remote Management (WinRM) service implements the WS-Management protocol for remote management. WS-Management is a standard web services protocol used for remote software and hardware management. The WinRM service listens on the network for WS-Management requests and processes them. The WinRM Service needs to be configured with a listener using winrm.cmd command line tool or through Group Policy in order for it to listen over the network. The WinRM service provides access to WMI data and enables event collection. Event collection and subscription to events require that the service is running. WinRM messages use HTTP and HTTPS as transports. The WinRM service does not depend on IIS but is preconfigured to share a port with IIS on the same machine.  The WinRM service reserves the /wsman URL prefix. To prevent conflicts with IIS, administrators should ensure that any websites hosted on IIS do not use the /wsman URL prefix.', interactive: false, pid: 932, service_flags: 0, reset_period: 86400, reboot_message: nil, command: nil, num_actions: 3, actions: { 1 => { action_type: 'restart', delay: 120000 }, 2 => { action_type: 'restart', delay: 300000 }, 3 => { action_type: 'none', delay: 0 } }, delayed_start: 0),
      double('Struct::ServiceInfo', service_name: 'WLMS', display_name: 'Windows Licensing Monitoring Service', service_type: 'own process', current_state: 'running', controls_accepted: ['shutdown'], win32_exit_code: 0, service_specific_exit_code: 0, check_point: 0, wait_hint: 0, binary_path_name: 'C:\\Windows\\system32\\wlms\\wlms.exe', start_type: 'auto start', error_control: 'critical', load_order_group: '', tag_id: 0, start_name: 'LocalSystem', dependencies: [], description: 'This service monitors the Windows software license state.', interactive: false, pid: 1084, service_flags: 0, reset_period: 120000, reboot_message: nil, command: nil, num_actions: 1, actions: { 1 => { action_type: 'reboot', delay: 10000 } }, delayed_start: 0),
    ])
    allow(Win32::Service).to receive(:exists?).and_return(true)
    allow(Win32::Service).to receive(:configure).and_return(Win32::Service)
    allow(Chef::ReservedNames::Win32::Security).to receive(:get_account_right).and_return([])
    allow(Chef::ReservedNames::Win32::Security).to receive(:add_account_right).with('LocalSystem', 'SeServiceLogonRight').and_return(0)
  end

  after(:each) do
    Win32::Service.send(:remove_const, "AUTO_START") if defined?(Win32::Service::AUTO_START)
    Win32::Service.send(:remove_const, "DEMAND_START") if defined?(Win32::Service::DEMAND_START)
    Win32::Service.send(:remove_const, "DISABLED") if defined?(Win32::Service::DISABLED)
  end

  it "sets the current resources service name to the new resources service name" do
    provider.load_current_resource
    expect(provider.current_resource.service_name).to eq("chef")
  end

  it "returns the current resource" do
    expect(provider.load_current_resource).to equal(provider.current_resource)
  end

  it "sets the current resources start type" do
    provider.load_current_resource
    expect(provider.current_resource.enabled).to be_truthy
  end

  context "service does not exist" do
    before do
      allow(Win32::Service).to receive(:exists?).with(anything).and_return(false)
    end

    %w(running enabled startup_type error_control binary_path_name
      load_order_group dependencies run_as_user display_name ).each do |prop|
        it  "does not set #{prop}" do
          expect(provider.current_resource.running).to be_nil
        end
      end
  end

  context "service exists" do
    before do
      allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
        double("Struct::ServiceConfigInfo",
          service_type: 'share process',
          start_type: 'demand start',
          error_control: 'normal',
          binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted',
          load_order_group: 'TDI',
          tag_id: 0,
          dependencies: %w(NSI Tdx Afd),
          service_start_name: 'NT Authority\\LocalService',
          display_name: 'DHCP Client'
        ))
    end

    context 'start type is neither AUTO START or DISABLED' do
      before do
        allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
          double("Struct::ServiceConfigInfo",
            service_type: 'share process',
            start_type: 'demand start',
            error_control: 'normal',
            binary_path_name: 'C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted',
            load_order_group: 'TDI',
            tag_id: 0,
            dependencies: %w(NSI Tdx Afd),
            service_start_name: 'NT Authority\\LocalService',
            display_name: 'DHCP Client'
          ))
      end

      it "does not set the current resources enabled" do
        provider.load_current_resource
        expect(provider.current_resource.enabled).to be_nil
      end
    end

    it "sets the current resources running to true if it's running" do
      allow(provider).to receive(:current_state).and_return("running")
      provider.load_current_resource
      expect(provider.current_resource.running).to be true
    end

    it "sets the current resources running to false if it's in any other state" do
      allow(provider).to receive(:current_state).and_return("other state")
      provider.load_current_resource
      expect(provider.current_resource.running).to be false
    end

    it "sets startup_type" do
      expect(provider.current_resource.startup_type).to be_truthy
    end

    it "sets error_control" do
      provider.load_current_resource
      expect(provider.current_resource.error_control).to be_truthy
    end

    it "sets binary_path_name" do
      provider.load_current_resource
      expect(provider.current_resource.binary_path_name).to be_truthy
    end

    it "sets load_order_group" do
      provider.load_current_resource
      expect(provider.current_resource.load_order_group).to be_truthy
    end

    it "sets dependencies" do
      provider.load_current_resource
      expect(provider.current_resource.dependencies).to be_truthy
    end

    it "sets run_as_user" do
      provider.load_current_resource
      expect(provider.current_resource.run_as_user).to be_truthy
    end

    it "sets display_name" do
      provider.load_current_resource
      expect(provider.current_resource.display_name).to be_truthy
    end

    context "delayed start" do
      it "sets delayed start" do
        provider.load_current_resource
        expect(provider.current_resource.delayed_start).to be_truthy
      end
    end
  end

  # current_resource.service_name(new_resource.service_name) // DONE
  #
  # if Win32::Service.exists?(current_resource.service_name)
  #   current_resource.running(current_state == RUNNING)
  #   Chef::Log.debug "#{new_resource} running: #{current_resource.running}"
  #   case current_start_type
  #   when AUTO_START
  #     current_resource.enabled(true)
  #   when DISABLED
  #     current_resource.enabled(false)
  #   end
  #   Chef::Log.debug "#{new_resource} enabled: #{current_resource.enabled}"
  #
  #   config_info = Win32::Service.config_info(current_resource.service_name)
  #   current_resource.service_type(get_service_type(config_info.service_type))    if config_info.service_type
  #   current_resource.startup_type(get_start_type(config_info.start_type))        if config_info.start_type
  #   current_resource.error_control(get_error_control(config_info.error_control)) if config_info.error_control
  #   current_resource.binary_path_name(config_info.binary_path_name) if config_info.binary_path_name
  #   current_resource.load_order_group(config_info.load_order_group) if config_info.load_order_group
  #   current_resource.dependencies(config_info.dependencies)         if config_info.dependencies
  #   current_resource.run_as_user(config_info.service_start_name)    if config_info.service_start_name
  #   current_resource.display_name(config_info.display_name)         if config_info.display_name
  #
  #   if delayed_start = current_delayed_start
  #     current_resource.delayed_start(delayed_start)
  #   end
  # end


  describe Chef::Provider::Service::Windows, "start_service" do
    before(:each) do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "running"))
    end

    it "calls the start command if one is specified" do
      new_resource.start_command "sc start chef"
      expect(provider).to receive(:shell_out!).with("#{new_resource.start_command}").and_return("Starting custom service")
      provider.start_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "uses the built-in command if no start command is specified" do
      expect(Win32::Service).to receive(:start).with(new_resource.service_name)
      provider.start_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "does nothing if the service does not exist" do
      allow(Win32::Service).to receive(:exists?).with(new_resource.service_name).and_return(false)
      expect(Win32::Service).not_to receive(:start).with(new_resource.service_name)
      provider.start_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "does nothing if the service is running" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:start).with(new_resource.service_name)
      provider.start_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "raises an error if the service is paused" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "paused"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:start).with(new_resource.service_name)
      expect { provider.start_service }.to raise_error( Chef::Exceptions::Service )
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "waits and continues if the service is in start_pending" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "start pending"),
        double("StatusStruct", :current_state => "start pending"),
        double("StatusStruct", :current_state => "running"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:start).with(new_resource.service_name)
      provider.start_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "fails if the service is in stop_pending" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stop pending"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:start).with(new_resource.service_name)
      expect { provider.start_service }.to raise_error( Chef::Exceptions::Service )
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    describe "running as a different account" do
      let(:old_run_as_user) { new_resource.run_as_user }
      let(:old_run_as_password) { new_resource.run_as_password }

      before do
        new_resource.run_as_user(".\\wallace")
        new_resource.run_as_password("Wensleydale")
      end

      after do
        new_resource.run_as_user(old_run_as_user)
        new_resource.run_as_password(old_run_as_password)
      end

      it "calls #grant_service_logon if the :run_as_user and :run_as_password attributes are present" do
        expect(Win32::Service).to receive(:start)
        expect(provider).to receive(:grant_service_logon).and_return(true)
        provider.start_service
      end

      it "does not grant user SeServiceLogonRight if it already has it" do
        expect(Win32::Service).to receive(:start)
        expect(Chef::ReservedNames::Win32::Security).to receive(:get_account_right).with("wallace").and_return([service_right])
        expect(Chef::ReservedNames::Win32::Security).not_to receive(:add_account_right).with("wallace", service_right)
        provider.start_service
      end
    end
  end

  describe Chef::Provider::Service::Windows, "stop_service" do

    before(:each) do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"),
        double("StatusStruct", :current_state => "stopped"))
    end

    it "calls the stop command if one is specified" do
      new_resource.stop_command "sc stop chef"
      expect(provider).to receive(:shell_out!).with("#{new_resource.stop_command}").and_return("Stopping custom service")
      provider.stop_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "uses the built-in command if no stop command is specified" do
      expect(Win32::Service).to receive(:stop).with(new_resource.service_name)
      provider.stop_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "does nothing if the service does not exist" do
      allow(Win32::Service).to receive(:exists?).with(new_resource.service_name).and_return(false)
      expect(Win32::Service).not_to receive(:stop).with(new_resource.service_name)
      provider.stop_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "does nothing if the service is stopped" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stopped"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:stop).with(new_resource.service_name)
      provider.stop_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "raises an error if the service is paused" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "paused"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:start).with(new_resource.service_name)
      expect { provider.stop_service }.to raise_error( Chef::Exceptions::Service )
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "waits and continue if the service is in stop_pending" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stop pending"),
        double("StatusStruct", :current_state => "stop pending"),
        double("StatusStruct", :current_state => "stopped"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:stop).with(new_resource.service_name)
      provider.stop_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "fails if the service is in start_pending" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "start pending"))
      provider.load_current_resource
      expect(Win32::Service).not_to receive(:stop).with(new_resource.service_name)
      expect { provider.stop_service }.to raise_error( Chef::Exceptions::Service )
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

    it "passes custom timeout to the stop command if provided" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"))
      new_resource.timeout 1
      expect(Win32::Service).to receive(:stop).with(new_resource.service_name)
      Timeout.timeout(2) do
        expect { provider.stop_service }.to raise_error(Timeout::Error)
      end
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

  end

  describe Chef::Provider::Service::Windows, "restart_service" do

    it "calls the restart command if one is specified" do
      new_resource.restart_command "sc restart"
      expect(provider).to receive(:shell_out!).with("#{new_resource.restart_command}")
      provider.restart_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "stops then starts the service if it is running" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "running"),
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "running"))
      expect(Win32::Service).to receive(:stop).with(new_resource.service_name)
      expect(Win32::Service).to receive(:start).with(new_resource.service_name)
      provider.restart_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "just starts the service if it is stopped" do
      allow(Win32::Service).to receive(:status).with(new_resource.service_name).and_return(
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "stopped"),
        double("StatusStruct", :current_state => "running"))
      expect(Win32::Service).to receive(:start).with(new_resource.service_name)
      provider.restart_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "does nothing if the service does not exist" do
      allow(Win32::Service).to receive(:exists?).with(new_resource.service_name).and_return(false)
      expect(Win32::Service).not_to receive(:stop).with(new_resource.service_name)
      expect(Win32::Service).not_to receive(:start).with(new_resource.service_name)
      provider.restart_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end

  end

  describe Chef::Provider::Service::Windows, "enable_service" do
    before(:each) do
      allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "disabled"))
    end

    it "enables service" do
      expect(Win32::Service).to receive(:configure).with(:service_name => new_resource.service_name, :start_type => Win32::Service::AUTO_START)
      provider.enable_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "does nothing if the service does not exist" do
      allow(Win32::Service).to receive(:exists?).with(new_resource.service_name).and_return(false)
      expect(Win32::Service).not_to receive(:configure)
      provider.enable_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end
  end

  describe Chef::Provider::Service::Windows, "action_enable" do
    it "does nothing if the service is enabled" do
      allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "auto start"))
      expect(provider).not_to receive(:enable_service)
      provider.action_enable
    end

    it "enables the service if it is not set to automatic start" do
      allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "disabled"))
      expect(provider).to receive(:enable_service)
      provider.action_enable
    end
  end

  describe Chef::Provider::Service::Windows, "action_disable" do
    it "does nothing if the service is disabled" do
      allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "disabled"))
      expect(provider).not_to receive(:disable_service)
      provider.action_disable
    end

    it "disables the service if it is not set to disabled" do
      allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "auto start"))
      expect(provider).to receive(:disable_service)
      provider.action_disable
    end
  end

  describe Chef::Provider::Service::Windows, "disable_service" do
    before(:each) do
      allow(Win32::Service).to receive(:config_info).with(new_resource.service_name).and_return(
        double("ConfigStruct", :start_type => "auto start"))
    end

    it "disables service" do
      expect(Win32::Service).to receive(:configure)
      provider.disable_service
      expect(new_resource.updated_by_last_action?).to be_truthy
    end

    it "does nothing if the service does not exist" do
      allow(Win32::Service).to receive(:exists?).with(new_resource.service_name).and_return(false)
      expect(Win32::Service).not_to receive(:configure)
      provider.disable_service
      expect(new_resource.updated_by_last_action?).to be_falsey
    end
  end

  describe Chef::Provider::Service::Windows, "action_configure_startup" do
    { :automatic => "auto start", :manual => "demand start", :disabled => "disabled" }.each do |type, win32|
      it "sets the startup type to #{type} if it is something else" do
        new_resource.startup_type(type)
        allow(provider).to receive(:current_start_type).and_return("fire")
        expect(provider).to receive(:set_startup_type).with(type)
        provider.action_configure_startup
      end

      it "leaves the startup type as #{type} if it is already set" do
        new_resource.startup_type(type)
        allow(provider).to receive(:current_start_type).and_return(win32)
        expect(provider).not_to receive(:set_startup_type).with(type)
        provider.action_configure_startup
      end
    end
  end

  describe Chef::Provider::Service::Windows, "set_start_type" do
    it "when called with :automatic it calls Win32::Service#configure with Win32::Service::AUTO_START" do
      expect(Win32::Service).to receive(:configure).with(:service_name => new_resource.service_name, :start_type => Win32::Service::AUTO_START)
      provider.send(:set_startup_type, :automatic)
    end

    it "when called with :manual it calls Win32::Service#configure with Win32::Service::DEMAND_START" do
      expect(Win32::Service).to receive(:configure).with(:service_name => new_resource.service_name, :start_type => Win32::Service::DEMAND_START)
      provider.send(:set_startup_type, :manual)
    end

    it "when called with :disabled it calls Win32::Service#configure with Win32::Service::DISABLED" do
      expect(Win32::Service).to receive(:configure).with(:service_name => new_resource.service_name, :start_type => Win32::Service::DISABLED)
      provider.send(:set_startup_type, :disabled)
    end

    it "raises an exception when given an unknown start type" do
      expect { provider.send(:set_startup_type, :fire_truck) }.to raise_error(Chef::Exceptions::ConfigurationError)
    end
  end

  shared_context "testing private methods" do

    let(:private_methods) do
      described_class.private_instance_methods
    end

    before do
      described_class.send(:public, *private_methods)
    end

    after do
      described_class.send(:private, *private_methods)
    end
  end

  describe "grant_service_logon" do
    include_context "testing private methods"

    let(:username) { "unit_test_user" }

    it "calls win32 api to grant user SeServiceLogonRight" do
      expect(Chef::ReservedNames::Win32::Security).to receive(:add_account_right).with(username, service_right)
      expect(provider.grant_service_logon(username)).to equal true
    end

    it "strips '.\' from user name when sending to win32 api" do
      expect(Chef::ReservedNames::Win32::Security).to receive(:add_account_right).with(username, service_right)
      expect(provider.grant_service_logon(".\\#{username}")).to equal true
    end

    it "raises an exception when the grant fails" do
      expect(Chef::ReservedNames::Win32::Security).to receive(:add_account_right).and_raise(Chef::Exceptions::Win32APIError, "barf")
      expect { provider.grant_service_logon(username) }.to raise_error(Chef::Exceptions::Service)
    end
  end

  describe "cleaning usernames" do
    include_context "testing private methods"

    it "correctly reformats usernames to create valid filenames" do
      expect(provider.clean_username_for_path("\\\\problem username/oink.txt")).to eq("_problem_username_oink_txt")
      expect(provider.clean_username_for_path("boring_username")).to eq("boring_username")
    end

    it "correctly reformats usernames for the policy file" do
      expect(provider.canonicalize_username(".\\maryann")).to eq("maryann")
      expect(provider.canonicalize_username("maryann")).to eq("maryann")

      expect(provider.canonicalize_username("\\\\maryann")).to eq("maryann")
      expect(provider.canonicalize_username("mydomain\\\\maryann")).to eq("mydomain\\\\maryann")
      expect(provider.canonicalize_username("\\\\mydomain\\\\maryann")).to eq("mydomain\\\\maryann")
    end
  end
end
