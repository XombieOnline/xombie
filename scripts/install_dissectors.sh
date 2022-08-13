#!/bin/bash

SCRIPT_RELATIVE_DIR=$(dirname "${BASH_SOURCE[0]}") 

CONFIG_DIR="$XDG_CONFIG_HOME"

if [ -z "$CONFIG_DIR" ]; then
	CONFIG_DIR="$HOME/.config"
fi

PLUGIN_DIR="$CONFIG_DIR/wireshark/plugins"

if [[ -f "$PLUGIN_DIR" ]]; then
	mkdir -p "$PLUGIN_DIR"
fi

cp $SCRIPT_RELATIVE_DIR/*.lua "$PLUGIN_DIR" 
