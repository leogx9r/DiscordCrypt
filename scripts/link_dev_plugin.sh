#!/bin/bash

# Resolve the plugin path.
plugin_path=~/.config/BetterDiscord/plugins/discordCrypt.plugin.js

# Remove any old refs.
rm ${plugin_path}

# Link to the build.
ln -s "`pwd`/build/discordCrypt.plugin.js" "${plugin_path}"
