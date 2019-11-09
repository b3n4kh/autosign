module Autosign
  module Validators
    require 'rbvmomi'
    # Validate by checking for a secret in vmware annotation.
    #
    # @example validate CSRs when the vmware is under the specific path and has a password in the anotation set.
    #   # In /etc/autosign.conf, include the following configuration:
    #   [vmware]
    #   vcenter_host = foo
    #   vcenter_user = user
    #   vcenter_password = password
    #   vcenter_datacenter = datacenter
    #
    class Vmware < Autosign::Validator
      def name
        "vmware"
      end

      private

      def perform_validation(password, certname, raw_csr)
        @log.debug "validating against vmware api"
        has_failed = false
        vim = RbVmomi::VIM.connect(host: settings['vcenter_host'], user: settings['vcenter_user'], password: settings['vcenter_password'])
        dc = vim.serviceInstance.find_datacenter(settings['vcenter_datacenter']) || has_failed = true
        vm = dc.find_vm(certname) || dc.find_vm(certname.split('.')[0]) || has_failed = true
        password == vm.config.annotation.to_s || has_failed = true
        result = ! has_failed
        @log.debug "validation result: " + result.to_s
        return result
      end

      def default_settings
        {
          'vcenter_host' => ENV["VCENTER_HOTS"]
          'vcenter_user' => ENV["VCENTER_USER"]
          'vcenter_password' => ENV["VCENTER_PASSWORD"]
          'vcenter_datacenter' => ENV["VCENTER_DATACENTER"]
        }
      end

    def validate_settings(settings)
      @log.debug "validating settings: " + settings.to_s
      true
    end

    end
  end
end
