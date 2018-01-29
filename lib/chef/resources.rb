#
# Author:: Daniel DeLeo (<dan@chef.io>)
# Copyright:: Copyright 2010-2016, Chef Software, Inc.
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

require "chef/resource/apt_package"
require "chef/resource/apt_preference"
require "chef/resource/apt_repository"
require "chef/resource/apt_update"
require "chef/resource/bash"
require "chef/resource/batch"
require "chef/resource/breakpoint"
require "chef/resource/cookbook_file"
require "chef/resource/chef_gem"
require "chef/resource/chocolatey_package"
require "chef/resource/cron"
require "chef/resource/csh"
require "chef/resource/directory"
require "chef/resource/dpkg_package"
require "chef/resource/dnf_package"
require "chef/resource/dsc_script"
require "chef/resource/dsc_resource"
require "chef/resource/erl_call"
require "chef/resource/execute"
require "chef/resource/file"
require "chef/resource/freebsd_package"
require "chef/resource/ips_package"
require "chef/resource/gem_package"
require "chef/resource/git"
require "chef/resource/group"
require "chef/resource/http_request"
require "chef/resource/homebrew_package"
require "chef/resource/ifconfig"
require "chef/resource/ksh"
require "chef/resource/launchd"
require "chef/resource/link"
require "chef/resource/log"
require "chef/resource/macports_package"
require "chef/resource/mdadm"
require "chef/resource/mount"
require "chef/resource/ohai"
require "chef/resource/openbsd_package"
require "chef/resource/openssl_dhparam"
require "chef/resource/openssl_rsa_private_key"
require "chef/resource/openssl_rsa_public_key"
require "chef/resource/package"
require "chef/resource/pacman_package"
require "chef/resource/paludis_package"
require "chef/resource/perl"
require "chef/resource/portage_package"
require "chef/resource/powershell_script"
require "chef/resource/osx_profile"
require "chef/resource/python"
require "chef/resource/reboot"
require "chef/resource/registry_key"
require "chef/resource/remote_directory"
require "chef/resource/remote_file"
require "chef/resource/rpm_package"
require "chef/resource/solaris_package"
require "chef/resource/route"
require "chef/resource/ruby"
require "chef/resource/ruby_block"
require "chef/resource/scm"
require "chef/resource/script"
require "chef/resource/service"
require "chef/resource/systemd_unit"
require "chef/resource/windows_service"
require "chef/resource/subversion"
require "chef/resource/smartos_package"
require "chef/resource/template"
require "chef/resource/user"
require "chef/resource/user/aix_user"
require "chef/resource/user/dscl_user"
require "chef/resource/user/linux_user"
require "chef/resource/user/pw_user"
require "chef/resource/user/solaris_user"
require "chef/resource/user/windows_user"
require "chef/resource/whyrun_safe_ruby_block"
require "chef/resource/windows_env"
require "chef/resource/windows_package"
require "chef/resource/yum_package"
require "chef/resource/yum_repository"
require "chef/resource/lwrp_base"
require "chef/resource/bff_package"
require "chef/resource/zypper_package"
require "chef/resource/zypper_repository"
require "chef/resource/cab_package"
require "chef/resource/powershell_package"
require "chef/resource/msu_package"
require "chef/resource/windows_task"
require "chef/resource/windows_path"
