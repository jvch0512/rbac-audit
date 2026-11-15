require "./audit"

def usage : Int32
  STDERR.puts "usage: rbac-audit PATH [--tsv] [--fail-on medium|high|critical]\nExit: 0 ok, 1 findings at or above --fail-on, 2 bad input."
  2
end

def run(args : Array(String)) : Int32
  path = nil
  tsv = false
  fail_on = nil
  i = 0
  while i < args.size
    a = args[i]
    if a == "--tsv"
      tsv = true
    elsif a == "--fail-on"
      i += 1
      return usage if i >= args.size || !%w(medium high critical).includes?(args[i])
      fail_on = args[i]
    elsif a.starts_with?("-")
      return usage
    elsif path
      return usage
    else
      path = a
    end
    i += 1
  end
  return usage if path.nil?
  unless File.exists?(path)
    STDERR.puts "error: no such file or directory: #{path}"
    return 2
  end
  files = [] of {String, String}
  if File.directory?(path)
    base = path.rstrip('/')
    Dir.glob(File.join(base, "**", "*.json")).sort.each do |f|
      files << {f[(base.size + 1)..], f} if File.file?(f)
    end
  else
    files << {File.basename(path), path}
  end
  all = [] of RbacAudit::Finding
  files.each do |label, f|
    next if File.size(f) > 20_000_000
    all.concat(RbacAudit.audit(File.read(f).scrub, label))
  end
  sorted = RbacAudit.sort(all)
  head = "#{files.size} files, #{sorted.size} findings"
  puts(tsv ? "# #{head}" : head)
  sorted.each do |f|
    if tsv
      puts [f.sev, f.rule, f.where, f.msg].join("\t")
    else
      puts "%-8s %s %s" % [f.sev.upcase, f.rule, f.where]
      puts "         #{f.msg}"
    end
  end
  if fail_on
    floor = RbacAudit::RANK[fail_on]
    return 1 if sorted.any? { |f| RbacAudit::RANK[f.sev] <= floor }
  end
  0
end

exit run(ARGV)
