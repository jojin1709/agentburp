#!/usr/bin/env bash
# Bash/Zsh Tab-Completion for agentburp
# Developed by JOJIN JOHN

_agentburp_completions() {
    local cur prev words cword
    _init_completion || return

    local subcommands="proxy hist repeat fuzz diff scan report workspace mcp-serve"

    if [ "$cword" -eq 1 ]; then
        COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )
        return 0
    fi

    case "${words[1]}" in
        proxy)
            COMPREPLY=( $(compgen -W "start --addr --scope" -- "$cur") )
            ;;
        hist)
            COMPREPLY=( $(compgen -W "list show --host --method --status --body --limit" -- "$cur") )
            ;;
        repeat)
            COMPREPLY=( $(compgen -W "--set --body --scope" -- "$cur") )
            ;;
        fuzz)
            COMPREPLY=( $(compgen -W "--param --wordlist --range-from --range-to --anomalies --confirm --scope" -- "$cur") )
            ;;
        report)
            COMPREPLY=( $(compgen -W "--format hackerone bugcrowd generic --finding-id" -- "$cur") )
            ;;
        workspace)
            COMPREPLY=( $(compgen -W "use current" -- "$cur") )
            ;;
        mcp-serve)
            COMPREPLY=( $(compgen -W "--scope" -- "$cur") )
            ;;
    esac
}

complete -F _agentburp_completions agentburp
