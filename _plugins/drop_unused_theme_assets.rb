UNUSED_THEME_ASSETS = %r{
  \A/assets/(
    style\.css |
    life-carousel\.js |
    life-in-weeks\.css |
    images/ |
    design_assets/
  )
}x.freeze

Jekyll::Hooks.register :site, :post_read do |site|
  theme_root = site.theme&.root
  next if theme_root.nil?

  site.static_files.reject! do |file|
    file.relative_path.match?(UNUSED_THEME_ASSETS) &&
      file.path.start_with?(theme_root)
  end
end
