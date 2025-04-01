#!/bin/bash
while getopts ":n:a:vh" opt; do
  case $opt in
    n) name=$OPTARG ;;
    a) age=$OPTARG ;;
    v) echo "You used -$opt option" ;;
    h) echo "Usage: $0 OPTIONS [-navh]"; exit 1 ;;
    ?) echo "Invalid option. Try $0 -h"; exit 1 ;;
  esac
done

if [[ -n "$name" && -n "$age" ]]; then
  echo "Name: $name"
  echo "Age: $age"
else
  echo -e "\nPlease, provide name [-n] and age [-a]. \ni.e. $0 -n Bob -a 10\n"
fi