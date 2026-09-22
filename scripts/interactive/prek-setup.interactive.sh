#!/usr/bin/env bash

# Options

set -euo pipefail

# Data

package_manager=""

# Functions

isPackageManager() {
    echo -e "Looking for Package Manager.\n"
    if [[ -n ${package_manager} ]]; then
        echo -e "Package Manager found.\n"
    else
        echo -e "Package Manager not found.\n"
        choosePackageManager
    fi
}

choosePackageManager() {
    echo "Do you utilize pip or uv?"
    options=("pip" "uv")
    select option in "${options[@]}"; do
        echo -e "The selected option was $option\n"
        case $option in
        pip)
            package_manager="$option"
            echo -e "Package Manager set to ${package_manager}\n"
            break
            ;;
        uv)
            package_manager="$option"
            echo -e "Package Manager set to ${package_manager}\n"
            break
            ;;
        esac
    done
}

installPrek() {
    case ${package_manager} in
    pip)
        echo -e "Now downloading prek via pip...\n"
        pip install prek
        echo -e "Download successful.\n"
        ;;
    uv)
        echo -e "Now downloading prek via uv...\n"
        uv add prek
        echo -e "Download successful.\n"
        ;;
    *)
        echo -e "Package Manager not found.\n"
        choosePackageManager
        installPrek
        ;;
    esac
}

installHooks() {
    echo -e "Commencing installation of prek hooks...\n"
    prek install
    echo -e "Installation successful.\n"
    # echo "Would you like to install the prek hooks?"
    # options=( "yes" "no" )
    # select option in ${options[@]}; do
    #     echo -e "The selected option was $option\n"
    #     case $option in
    #         yes )
    #             echo -e "Commencing installation of prek hooks\n"
    #             prek install
    #             ;;
    #         no )
    #             echo -e "Prek hooks will not be downloaded.\n"
    #             ;;
    #     esac
    # done
}

runHooks() {
    echo -e "Running prek hooks on all files...\n"
    prek run --all-files
    echo -e "Hook execution finished.\n"
    # echo "Would you like to run your hooks against all files (test the hooks)?"
    # options=( "yes" "no" )
    # select option in ${options[@]}; do
    #     echo -e "The selected option was $option\n"
    #     case $option in
    #         yes )
    #             echo -e "Commencing installation of prek hooks\n"
    #             installPrek
    #             ;;
    #         no )
    #             echo -e "Prek hooks will not be downloaded.\n"
    #             ;;
    #     esac
    # done
}

setupPrek() {
    echo -e "Press numbers to select different options.\n"

    echo "Would you like to install prek?"
    options=("yes" "no")
    select option in "${options[@]}"; do
        echo -e "The selected option was $option\n"
        case $option in
        yes)
            echo -e "Commencing installation of prek...\n"
            installPrek
            echo -e "Installation finished."
            break
            ;;
        no)
            echo -e "Prek will not be downloaded.\n"
            break
            ;;
        esac
    done

    echo "Would you like to install the prek hooks?"
    options=("yes" "no")
    select option in "${options[@]}"; do
        echo -e "The selected option was $option\n"
        case $option in
        yes)
            installHooks
            break
            ;;
        no)
            echo -e "Prek hooks will not be downloaded.\n"
            break
            ;;
        esac
    done

    echo "Would you like to run your hooks against all files (test the hooks)?"
    options=("yes" "no")
    select option in "${options[@]}"; do
        echo -e "The selected option was $option\n"
        case $option in
        yes)
            runHooks
            break
            ;;
        no)
            echo -e "Prek hooks will not be downloaded.\n"
            break
            ;;
        esac
    done
}

# Displays help info to the user
displayHelpInfo() {
    echo "This bash script is for managing the prek (rust pre-commit) installation and hook setup:"
    echo
    echo "Syntax: prek_setup [help|setup|menu]"
    echo "options:"
    echo "help     Print this help message."
    echo "setup    Setup prek and hooks."
    echo "menu     Starts a menu with more fine-grained options and controls."
    echo
}

# Initializes a little menu that can be used to manage prek
startMenu() {
    while true; do
        options=("quit" "setup" "select package manager" "install prek" "install prek hooks" "test hooks")
        # Tracks whether the select loop ended through a menu choice or because
        # stdin closed (Ctrl+D, or the script being run non-interactively).
        selection_made=""
        select option in "${options[@]}"; do
            selection_made="yes"
            case "$option" in
            "q" | "quit" | "exit")
                break 2 # Exit the while loop, not just the case block
                ;;
            "setup")
                setupPrek
                break
                ;;
            "select package manager")
                choosePackageManager
                break
                ;;
            "install prek")
                installPrek
                break
                ;;
            "install prek hooks")
                installHooks
                break
                ;;
            "test hooks")
                runHooks
                break
                ;;
            *)
                echo "Invalid input"
                break
                ;;
            esac
        done

        if [[ -z ${selection_made} ]]; then
            echo -e "
Input stream closed. Exiting menu."
            break
        fi
    done
}

# Main

case ${1:-} in
setup)
    setupPrek
    echo "prek was successfully set up"
    ;;
help)
    displayHelpInfo
    ;;
menu)
    startMenu
    ;;
"")
    startMenu
    ;;
*)
    echo "Input was invalid."
    echo "You can access the help menu by running the script with help."
    echo
    ;;
esac
