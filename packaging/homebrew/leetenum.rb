# packaging/homebrew/leetenum.rb — Homebrew formula for LeetEnum.
#
# Lives in the tap repo as Formula/leetenum.rb:
#
#   mkdir -p Formula
#   curl -fsSL -o Formula/leetenum.rb \
#     https://github.com/theleetsec/LeetSec-Tools/releases/download/v1.1.1/leetenum.rb
#   brew install --build-from-source ./Formula/leetenum.rb
#
# A copy is kept here so the formula is versioned alongside the code it
# installs; CI attaches the rendered formula to each release. A separate tap
# can be updated when HOMEBREW_TAP_TOKEN is configured.
#
# Design notes:
#   - LeetEnum is a bash program, so this is a source install with no compile
#     step. libexec holds the tree, bin/leetenum is a symlink, and leetenum.sh
#     resolves symlinks itself to find lib/.
#   - The Go tools are dependencies, not vendored. Homebrew already packages
#     most of them and keeping them separate means `brew upgrade` updates the
#     toolchain without touching the pipeline.
#   - massdns has no formula. `leetenum install` builds it, and the caveats say
#     so rather than the formula pretending DNS brute force works without it.
class Leetenum < Formula
  desc "Reconnaissance pipeline for authorised security assessments"
  homepage "https://github.com/theleetsec/LeetSec-Tools"
  url "https://github.com/theleetsec/LeetSec-Tools/archive/refs/tags/v1.1.1.tar.gz"
  # Replaced by CI on release; `brew fetch --build-from-source` prints the value.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/theleetsec/LeetSec-Tools.git", branch: "main"

  # tap-strip:begin
  # Everything between these markers is removed when CI renders the tap copy of
  # this formula. Bottles are built and attached by the tap's own workflow, so a
  # placeholder sha256 must never reach the tap — `brew install` would fail for
  # everyone until the bottle job replaced it. The block stays here so the
  # bottling policy is versioned with the formula it applies to.
  #
  # :all rather than per-architecture: nothing in this formula is architecture
  # specific, so one bottle serves Apple Silicon, Intel and Linux.
  bottle do
    sha256 cellar: :any_skip_relocation, all: "0000000000000000000000000000000000000000000000000000000000000000"
  end
  # tap-strip:end

  depends_on "bash"
  depends_on "coreutils"
  depends_on "jq"

  depends_on "httpx"
  depends_on "katana"
  depends_on "naabu"
  depends_on "nuclei"
  depends_on "subfinder"

  # amass, assetfinder, gotator, gowitness, puredns and waybackurls have no
  # formulae. `leetenum install` fetches them with pinned versions, and every
  # phase that needs one degrades with a warning instead of failing the run.
  depends_on "go" => :recommended

  def install
    libexec.install "leetenum.sh", "lib"
    chmod 0755, libexec/"leetenum.sh"
    bin.install_symlink libexec/"leetenum.sh" => "leetenum"

    # Homebrew's bash is the one that matters here: macOS ships 3.2 and the
    # pipeline supports it, but the formula depends on a modern bash so the
    # bottle behaves the same on both platforms.
    doc.install "README.md" if File.exist?("README.md")
    (pkgshare/"tests").install Dir["tests/*"] if Dir.exist?("tests")
  end

  def caveats
    <<~EOS
      The Go-based recon tools that Homebrew does not package, plus massdns,
      are installed separately:

        leetenum install

      massdns is required for DNS resolution and brute force. Without it,
      phases 2 through 4 return nothing and LeetEnum says so at startup.

      Check the environment at any time with:

        leetenum doctor

      Screenshots (phase 9) need a Chromium build:

        brew install --cask chromium

      Configuration and cache live under:
        #{ENV.fetch("XDG_CONFIG_HOME", "~/.config")}/leetsec
        #{ENV.fetch("XDG_CACHE_HOME", "~/.cache")}/leetsec
    EOS
  end

  test do
    # Three checks that need no network and no toolchain: the version banner,
    # help text, and that the symlinked entry point still locates lib/.
    assert_match "leetenum", shell_output("#{bin}/leetenum version")
    assert_match "PHASES",   shell_output("#{bin}/leetenum --help")

    # `doctor` exits non-zero when a required tool is absent — that is deliberate,
    # so it can be used as a CI gate — and puredns has no formula, so a fresh
    # install is expected to report it missing. Assert on the report, not the
    # status.
    report = shell_output("#{bin}/leetenum doctor 2>&1 || true")
    assert_match "Environment report", report
    assert_match "subfinder", report
  end
end
