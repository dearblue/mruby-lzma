MRuby::Gem::Specification.new("mruby-lzma") do |s|
  s.summary = "mruby bindings for lzma the compression library (unofficial)"
  s.version = "0.2"
  s.license = "BSD-2-Clause"
  s.author  = "dearblue"
  s.homepage = "https://github.com/dearblue/mruby-lzma"

  add_dependency "mruby-error", core: "mruby-error"
  add_dependency "mruby-string-ext", core: "mruby-string-ext"
  add_dependency "mruby-aux", github: "dearblue/mruby-aux"

  if s.cc.command =~ /\b(?:g?cc|clang)\d*\b/
    s.cc.flags << "-Wall" <<
                  "-Wno-shift-negative-value" <<
                  "-Wno-shift-count-negative" <<
                  "-Wno-shift-count-overflow" <<
                  "-Wno-missing-braces"
  end

  linker.libraries << "lzma"
end
