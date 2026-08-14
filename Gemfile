source "https://rubygems.org"

workspace = ENV.fetch("GITHUB_WORKSPACE")
File.write(File.join(workspace, "gemfile-actions-disabled.txt"), "CONTROLLED_PAGES_ACTIONS_DISABLED_SENTINEL\n")

gem "github-pages", "= 232"
