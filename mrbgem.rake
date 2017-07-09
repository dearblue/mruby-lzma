MRuby::Gem::Specification.new("mruby-lzma") do |s|
  s.summary = "mruby bindings for lzma the compression library (unofficial)"
  s.version = "0.1"
  s.license = "BSD-2-Clause"
  s.author  = "dearblue"
  s.homepage = "https://github.com/dearblue/mruby-lzma"

  add_dependency "mruby-error"
  add_dependency "mruby-string-ext"

  if s.cc.command =~ /\b(?:g?cc|clang)\d*\b/
    s.cc.flags << "-Wall" <<
                  "-Wno-shift-negative-value" <<
                  "-Wno-shift-count-negative" <<
                  "-Wno-shift-count-overflow" <<
                  "-Wno-missing-braces"
  end

  linker.libraries << "lzma"
end
