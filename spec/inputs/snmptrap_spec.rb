require "logstash/devutils/rspec/spec_helper"
require "logstash/devutils/rspec/shared_examples"
require 'logstash/inputs/snmptrap'

describe LogStash::Inputs::Snmptrap do

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
    manager = SNMP::Manager.new(:host => 'localhost', :port => 1061)
    def manager.send_request(trap, community, host, port)
      trap
    end
    manager
  end

  context 'v1' do

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
      expect( @event.get('host') ).to eql '192.168.1.11'
    end

  end

  context 'v2' do

    let(:trap) do
      trap = snmp_manager.trap_v2(1011, "1.3.6.1.2.1.1.1.0", ["1.2.3", "1.4.5.6"])
      trap.source_ip = '192.168.1.11'
      trap
    end

    before { @event = input.send :process_trap, trap }

    it "extract snmp payload" do
      expect( @event.get('message') ).to be_a String

      expect( @event.get('1.2.3') ).to eql 'Null'
      expect( @event.get('1.3.6.1.2.1.1.3.0') ).to eql '00:00:10.11' # uptime tick
    end

    it "sets source host" do
      expect( @event.get('host') ).to eql '192.168.1.11'
    end

  end

end
