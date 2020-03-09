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
end
