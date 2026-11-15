require "spec"
require "../src/audit"

def role(kind, name, rules, ns = nil)
  meta = ns ? %({"name":"#{name}","namespace":"#{ns}"}) : %({"name":"#{name}"})
  %({"kind":"#{kind}","metadata":#{meta},"rules":#{rules}})
end

def binding(kind, name, ref, subjects, refkind = "ClusterRole")
  %({"kind":"#{kind}","metadata":{"name":"#{name}"},"roleRef":{"kind":"#{refkind}","name":"#{ref}"},"subjects":#{subjects}})
end

def run(item)
  RbacAudit.audit(%({"kind":"List","items":[#{item}]}), "t.json")
end

def rules_of(f)
  f.map(&.rule)
end

describe "roles" do
  it "flags wildcard verbs on wildcard resources" do
    f = run(role("ClusterRole", "x", %([{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}])))
    rules_of(f).should eq ["RBAC002"]
    f[0].sev.should eq "high"
  end
  it "flags secret readers: high for cluster roles, medium for roles" do
    r = %([{"apiGroups":[""],"resources":["secrets"],"verbs":["get"]}])
    run(role("ClusterRole", "a", r))[0].sev.should eq "high"
    run(role("Role", "a", r, "ns"))[0].sev.should eq "medium"
  end
  it "ignores read of configmaps" do
    run(role("Role", "a", %([{"apiGroups":[""],"resources":["configmaps"],"verbs":["get"]}]), "ns")).should be_empty
  end
  it "flags pods/exec create" do
    rules_of(run(role("Role", "a", %([{"apiGroups":[""],"resources":["pods/exec"],"verbs":["create"]}]), "ns"))).should eq ["RBAC004"]
  end
  it "flags escalate, bind and impersonate" do
    f = run(role("ClusterRole", "a", %([{"apiGroups":["rbac.authorization.k8s.io"],"resources":["clusterroles"],"verbs":["escalate","bind"]}])))
    rules_of(f).should eq ["RBAC005"]
    f[0].msg.should contain "escalate, bind"
    rules_of(run(role("ClusterRole", "a", %([{"apiGroups":[""],"resources":["users"],"verbs":["impersonate"]}])))).should eq ["RBAC005"]
  end
  it "flags rights over rbac objects" do
    rules_of(run(role("ClusterRole", "a", %([{"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["create"]}])))).should eq ["RBAC006"]
  end
  it "does not flag read-only rbac access" do
    run(role("ClusterRole", "a", %([{"apiGroups":["rbac.authorization.k8s.io"],"resources":["rolebindings"],"verbs":["get","list"]}]))).should be_empty
  end
  it "skips system and built-in roles" do
    r = %([{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}])
    run(role("ClusterRole", "system:controller:x", r)).should be_empty
    run(role("ClusterRole", "admin", r)).should be_empty
  end
  it "handles roles without rules" do
    run(%({"kind":"Role","metadata":{"name":"empty"}})).should be_empty
  end
  it "ignores non-string entries" do
    run(role("Role", "a", %([{"resources":[1,null,"secrets"],"verbs":[true,"get"]}]), "ns"))[0].rule.should eq "RBAC003"
  end
end

describe "bindings" do
  it "grades cluster-admin by subject" do
    ca = ->(s : String) { run(binding("ClusterRoleBinding", "b", "cluster-admin", s)).map(&.sev) }
    ca.call(%([{"kind":"User","name":"alice"}])).should eq ["medium"]
    ca.call(%([{"kind":"ServiceAccount","name":"ci","namespace":"ci"}])).should eq ["high"]
    ca.call(%([{"kind":"Group","name":"system:authenticated"}])).should eq ["critical"]
    ca.call(%([{"kind":"Group","name":"system:serviceaccounts"}])).should eq ["critical"]
  end
  it "does not flag system:masters" do
    run(binding("ClusterRoleBinding", "b", "cluster-admin", %([{"kind":"Group","name":"system:masters"}]))).should be_empty
  end
  it "flags anonymous bindings as critical" do
    f = run(binding("ClusterRoleBinding", "b", "view", %([{"kind":"User","name":"system:anonymous"}])))
    rules_of(f).should eq ["RBAC008"]
    f[0].sev.should eq "critical"
  end
  it "allows the discovery roles for unauthenticated" do
    run(binding("ClusterRoleBinding", "b", "system:public-info-viewer", %([{"kind":"Group","name":"system:unauthenticated"}]))).should be_empty
  end
  it "flags default service account bindings" do
    rules_of(run(binding("RoleBinding", "b", "edit", %([{"kind":"ServiceAccount","name":"default","namespace":"shop"}])))).should eq ["RBAC007"]
  end
  it "does not flag built-in system bindings of default" do
    run(binding("ClusterRoleBinding", "system:x", "system:y", %([{"kind":"ServiceAccount","name":"default","namespace":"kube-system"}]))).should be_empty
  end
  it "handles a binding with no subjects" do
    run(%({"kind":"RoleBinding","metadata":{"name":"b"},"roleRef":{"name":"x"}})).should be_empty
  end
end

describe "input shapes" do
  it "reports invalid json as info" do
    f = RbacAudit.audit("{nope", "bad.json")
    rules_of(f).should eq ["RBAC000"]
    f[0].sev.should eq "info"
  end
  it "reports non kubernetes json" do
    rules_of(RbacAudit.audit(%({"a":1}), "o.json")).should eq ["RBAC000"]
    rules_of(RbacAudit.audit("[]", "o.json")).should eq ["RBAC000"]
    rules_of(RbacAudit.audit("42", "o.json")).should eq ["RBAC000"]
    rules_of(RbacAudit.audit(%("text"), "o.json")).should eq ["RBAC000"]
  end
  it "accepts a single object" do
    rules_of(RbacAudit.audit(role("ClusterRole", "x", %([{"resources":["*"],"verbs":["*"]}])), "s.json")).should eq ["RBAC002"]
  end
  it "accepts an array of lists" do
    txt = %([{"kind":"List","items":[#{role("ClusterRole", "x", %([{"resources":["*"],"verbs":["*"]}]))}]}])
    rules_of(RbacAudit.audit(txt, "a.json")).should eq ["RBAC002"]
  end
  it "survives wrong types" do
    RbacAudit.audit(%({"kind":"List","items":"x"}), "w.json")
    RbacAudit.audit(%({"kind":"List","items":[{"kind":"Role","metadata":5,"rules":"x"}]}), "w.json")
    RbacAudit.audit(%({"kind":"List","items":[{"kind":"RoleBinding","subjects":{"a":1},"roleRef":[]}]}), "w.json")
  end
  it "withstands 3000 random inputs" do
    rng = Random.new(7)
    pieces = ["{", "}", "[", "]", ",", ":", "\"kind\"", "\"Role\"", "\"items\"", "\"rules\"", "\"verbs\"", "\"*\"", "null", "1", "\"x\""]
    3000.times do
      s = String.build { |io| rng.rand(1..30).times { io << pieces.sample(rng) } }
      RbacAudit.audit(s, "f.json")
    end
  end
  it "sorts by severity first" do
    f = RbacAudit.sort([RbacAudit::Finding.new("medium", "B", "a", ""), RbacAudit::Finding.new("critical", "A", "z", "")])
    f.map(&.sev).should eq ["critical", "medium"]
  end
end
