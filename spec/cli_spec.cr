require "spec"

BIN = File.expand_path("../build/rbac-audit", __DIR__)

def cli(args : Array(String))
  so = IO::Memory.new
  se = IO::Memory.new
  st = Process.run(BIN, args, output: so, error: se)
  {st.exit_code, so.to_s, se.to_s}
end

describe "cli" do
  it "prints a human report and exits 0 by default" do
    code, so, _ = cli(["examples"])
    code.should eq 0
    so.should start_with "3 files, 12 findings"
    so.should contain "CRITICAL RBAC008"
  end
  it "prints tsv with a header" do
    code, so, _ = cli(["examples", "--tsv"])
    code.should eq 0
    so.lines[0].should eq "# 3 files, 12 findings"
    so.lines[1].split('\t').size.should eq 4
  end
  it "fails on --fail-on" do
    cli(["examples", "--fail-on", "critical"])[0].should eq 1
    cli(["examples/team-a.json", "--fail-on", "medium"])[0].should eq 0
  end
  it "exits 2 on bad input" do
    cli(["nope.json"])[0].should eq 2
    cli(["--bogus"])[0].should eq 2
    cli([] of String)[0].should eq 2
    cli(["examples", "--fail-on", "low"])[0].should eq 2
    cli(["examples", "extra"])[0].should eq 2
  end
end
