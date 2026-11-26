# Homebrew formula. Publish in a tap (e.g. PankajKrana/homebrew-tap) and install with:
#   brew install PankajKrana/tap/fuck-ads
#   sudo fuck-ads enable
class FuckAds < Formula
  desc "System-wide ad and tracker blocking (filtering DNS + browser extensions)"
  homepage "https://github.com/PankajKrana/fuck-ads"
  url "https://github.com/PankajKrana/fuck-ads/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "031c47b7893c2101c48fec83245fd9e3b6fbdbb1710fa2bdb30e74003ac890c2"
  license "MIT"
  head "https://github.com/PankajKrana/fuck-ads.git", branch: "main"

  depends_on "rust" => :build
  depends_on :macos

  def install
    system "cargo", "install", *std_cargo_args(path: "crates/fuck-ads-cli")
    bin.install_symlink "fuck-ads" => "fuck-ads-native-host"
    (share/"fuck-ads/filters").install Dir["filters/*.txt"]
    system "./browser/build.sh"
    (share/"fuck-ads").install "browser/dist/chromium", "browser/dist/firefox"
  end

  def caveats
    <<~EOS
      Turn protection on (installs the system service and routes DNS through it):
        sudo fuck-ads enable

      The service runs a root-owned copy of the binary. After `brew upgrade fuck-ads`, run:
        sudo fuck-ads enable && sudo fuck-ads restart

      Browser extensions (needed for in-page and YouTube ads):
        #{opt_share}/fuck-ads/chromium
        #{opt_share}/fuck-ads/firefox

      Before `brew uninstall fuck-ads`, run:
        sudo fuck-ads uninstall --yes
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/fuck-ads --version")
    system bin/"fuck-ads", "config", "validate"
  end
end
