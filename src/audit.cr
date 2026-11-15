require "json"

module RbacAudit
  RANK = {"critical" => 0, "high" => 1, "medium" => 2, "low" => 3, "info" => 4}

  record Finding, sev : String, rule : String, where : String, msg : String

  SECRET_READ = %w(get list watch *)
  ESCALATE    = %w(escalate bind impersonate)
  RBAC_KINDS  = %w(roles clusterroles rolebindings clusterrolebindings)
  RBAC_WRITE  = %w(create update patch delete *)
  BUILTIN     = %w(cluster-admin admin edit view)
  ANON_OK     = %w(system:public-info-viewer system:discovery system:basic-user)

  def self.strings(any : JSON::Any?) : Array(String)
    return [] of String if any.nil?
    arr = any.as_a?
    return [] of String if arr.nil?
    arr.compact_map(&.as_s?)
  end

  def self.dig_s(any : JSON::Any, *keys) : String
    cur = any
    keys.each do |k|
      h = cur.as_h?
      return "" if h.nil?
      nxt = h[k]?
      return "" if nxt.nil?
      cur = nxt
    end
    cur.as_s? || ""
  end

  def self.items(doc : JSON::Any) : Array(JSON::Any)
    if h = doc.as_h?
      if its = h["items"]?
        arr = its.as_a?
        if arr
          return arr
        end
        return [] of JSON::Any
      end
      return [doc] if h["kind"]?
    elsif a = doc.as_a?
      acc = [] of JSON::Any
      a.each { |x| acc.concat(items(x)) }
      return acc
    end
    [] of JSON::Any
  end

  def self.system_object?(obj : JSON::Any) : Bool
    name = dig_s(obj, "metadata", "name")
    return true if name.starts_with?("system:") || BUILTIN.includes?(name)
    labels = obj["metadata"]?.try(&.as_h?).try(&.["labels"]?).try(&.as_h?)
    if labels
      return true if labels["kubernetes.io/bootstrapping"]?.try(&.as_s?) == "rbac-defaults"
    end
    false
  end

  def self.audit(text : String, label : String) : Array(Finding)
    acc = [] of Finding
    doc = begin
      JSON.parse(text)
    rescue
      return [Finding.new("info", "RBAC000", label, "not valid JSON, ignored")]
    end
    objs = items(doc)
    kinds = %w(Role ClusterRole RoleBinding ClusterRoleBinding)
    objs = objs.select { |o| kinds.includes?(dig_s(o, "kind")) }
    return [Finding.new("info", "RBAC000", label, "no Role, ClusterRole, RoleBinding or ClusterRoleBinding found")] if objs.empty?

    objs.each do |o|
      kind = dig_s(o, "kind")
      name = dig_s(o, "metadata", "name")
      ns = dig_s(o, "metadata", "namespace")
      where = "#{label}:#{kind}/#{ns.empty? ? "" : ns + "/"}#{name}"
      if kind == "Role" || kind == "ClusterRole"
        next if system_object?(o)
        rules = o["rules"]?.try(&.as_a?) || ([] of JSON::Any)
        rules.each { |r| audit_rule(r, kind, where, acc) }
      else
        audit_binding(o, kind, where, acc)
      end
    end
    acc
  end

  def self.audit_rule(r : JSON::Any, kind : String, where : String, acc : Array(Finding))
    verbs = strings(r["verbs"]?)
    res = strings(r["resources"]?)
    groups = strings(r["apiGroups"]?)
    wild_v = verbs.includes?("*")
    wild_r = res.includes?("*")
    if wild_v && wild_r
      acc << Finding.new("high", "RBAC002", where, "wildcard verbs on wildcard resources: this role is cluster-admin in all but name")
    end
    core = groups.empty? || groups.includes?("") || groups.includes?("*")
    if core && (res.includes?("secrets") || wild_r) && verbs.any? { |v| SECRET_READ.includes?(v) } && !(wild_v && wild_r)
      sev = kind == "ClusterRole" ? "high" : "medium"
      acc << Finding.new(sev, "RBAC003", where, "can read secrets#{kind == "ClusterRole" ? " in every namespace" : ""}")
    end
    if core && (res.includes?("pods/exec") || res.includes?("pods/attach") || res.includes?("nodes/proxy")) && verbs.any? { |v| v == "create" || v == "get" || v == "*" }
      acc << Finding.new("high", "RBAC004", where, "can open a shell or attach inside pods or proxy to nodes: #{(res & %w(pods/exec pods/attach nodes/proxy)).join(", ")}")
    end
    esc = verbs & ESCALATE
    unless esc.empty?
      acc << Finding.new("high", "RBAC005", where, "verbs that bypass RBAC checks: #{esc.join(", ")}")
    end
    if (groups.includes?("rbac.authorization.k8s.io") || groups.includes?("*")) && !(wild_v && wild_r) &&
       (res.any? { |x| RBAC_KINDS.includes?(x) } || (wild_r && !wild_v)) && verbs.any? { |v| RBAC_WRITE.includes?(v) } && esc.empty?
      acc << Finding.new("medium", "RBAC006", where, "can create or change roles and bindings: a path to more privilege")
    end
  end

  def self.audit_binding(o : JSON::Any, kind : String, where : String, acc : Array(Finding))
    ref_kind = dig_s(o, "roleRef", "kind")
    ref_name = dig_s(o, "roleRef", "name")
    subjects = o["subjects"]?.try(&.as_a?) || ([] of JSON::Any)
    name = dig_s(o, "metadata", "name")
    default_builtin = name.starts_with?("system:") && ref_name.starts_with?("system:")
    subjects.each do |s|
      sk = dig_s(s, "kind")
      sn = dig_s(s, "name")
      sns = dig_s(s, "namespace")
      who = "#{sk} #{sns.empty? ? "" : sns + "/"}#{sn}"
      anon = sn == "system:anonymous" || sn == "system:unauthenticated"
      if anon && !ANON_OK.includes?(ref_name)
        acc << Finding.new("critical", "RBAC008", where, "#{who} is bound to #{ref_name}: anyone on the network gets these rights")
      end
      if ref_name == "cluster-admin" && ref_kind == "ClusterRole" && !(sk == "Group" && sn == "system:masters")
        sev = "medium"
        if anon || sn == "system:authenticated" || sn == "system:serviceaccounts"
          sev = "critical"
        elsif sk == "ServiceAccount"
          sev = "high"
        end
        acc << Finding.new(sev, "RBAC001", where, "#{who} is bound to cluster-admin")
      end
      if sk == "ServiceAccount" && sn == "default" && !default_builtin
        acc << Finding.new("medium", "RBAC007", where, "the default service account of #{sns.empty? ? "a namespace" : sns} is bound to #{ref_name}: every pod without its own account inherits it")
      end
    end
  end

  def self.sort(f : Array(Finding)) : Array(Finding)
    f.sort_by { |x| {RANK[x.sev], x.where, x.rule} }
  end
end
