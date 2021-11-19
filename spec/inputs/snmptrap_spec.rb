require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'
require 'logstash/inputs/snmptrap'

describe LogStash::Inputs::Snmptrap, :ecs_compatibility_support do

  it_behaves_like "an interruptible input plugin" do
    # as there is no mocking the run method will
    # raise a connection error and put the run method
    # into the sleep retry section loop
    # meaning that the stoppable sleep impl is tested
    let(:config) { {} }
  end

  let(:config) { Hash.new }

  subject(:input) { described_class.new(config) }

  let(:source_ip) { '192.168.1.11' }

  let(:snmp_manager) do
    SNMP::Manager.new.tap do |manager|
      def manager.send_request(trap, community, host, port)
        trap # dummy manager - we're just using the Manager API to create traps
      end
    end
  end

  ecs_compatibility_matrix(:disabled, :v1, :v8) do |ecs_select|

    let(:config) { super().merge 'ecs_compatibility' => ecs_compatibility }

    context 'with an SNMP v1 trap' do

      let(:trap) do
        trap = snmp_manager.trap_v1("enterprises.9", "10.1.2.3", :enterpriseSpecific, 42, 12345,
                                    [SNMP::VarBind.new("1.3.6.1.2.3.4", SNMP::Integer.new(111))])
        trap.source_ip = source_ip
        trap
      end

      before { @event = input.send :process_trap, trap }

      it "extract snmp payload" do
        expect( @event.get('message') ).to be_a String # #<SNMP::SNMPv1_Trap:0x664c6bbc @enterprise=[1.3.6.1.4.1.9] ... >
        expect( @event.get('1.3.6.1.2.3.4') ).to eql '111'
      end

      it "sets source host" do
        if ecs_select.active_mode == :disabled
          expect( @event.get('host') ).to eql source_ip
        else
          expect( @event.get('host') ).to eql 'ip' => source_ip
        end
      end

    end

    context 'with an SNMP v2 trap' do

      let(:trap) do
        trap = snmp_manager.trap_v2(1011, "1.3.6.1.2.1.1.1.0", ["1.2.3", "1.4.5.6"])
        trap.source_ip = source_ip
        trap
      end

      before { @event = input.send :process_trap, trap }

      it "extract snmp payload" do
        expect( @event.get('message') ).to be_a String

        expect( @event.get('1.2.3') ).to eql 'Null'
        expect( @event.get('1.3.6.1.2.1.1.3.0') ).to eql '00:00:10.11' # uptime tick
      end

      it "sets source host" do
        if ecs_select.active_mode == :disabled
          expect( @event.get('host') ).to eql source_ip
        else
          expect( @event.get('host') ).to eql 'ip' => source_ip
        end
      end

      context 'with target' do

        let(:config) { super().merge 'target' => '[snmp]' }

        it "extract snmp payload" do
          expect( @event.include?('1.2.3') ).to be false
          expect( @event.include?('1.3.6.1.2.1.1.3.0') ).to be false
          expect( @event.get('[snmp][1.2.3]') ).to eql 'Null'
          expect( @event.get('[snmp][1.3.6.1.2.1.1.3.0]') ).to eql '00:00:10.11' # uptime tick

          expect( @event.get('message') ).to be_a String
        end

        it "sets source host" do
          if ecs_select.active_mode == :disabled
            expect( @event.get('host') ).to eql source_ip
          else
            expect( @event.get('host') ).to eql 'ip' => source_ip
          end
        end

      end

    end

  end
end
