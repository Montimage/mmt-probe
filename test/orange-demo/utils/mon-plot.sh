#!/bin/bash

# This script uses gnuplot to plot a chart representing CPU/Memory monitoring result of a process

if [ "$#" -ne "1" ]; then
  echo "Convert result in file *.mon to a graph"
  echo "Usage: $0 file_name"
  exit 0
fi

#check if gnuplot is avaiable
if command -v gnuplot >/dev/null; then
   echo
else
   echo "You need to install gnuplot"
   exit 0
fi

INPUT=$1
OUTPUT="$INPUT".pdf

gnuplot << EOF
reset

#do not output now, just to test to make visible variables GPVAL_DATA_X_MIN:GPVAL_DATA_X_MAX
set terminal unknown

set xdata time
set timefmt "%H:%M:%S"
#set format x "%H:%M"
#set xtics 60
set xlabel "Time"


set ylabel "percent"


set y2label "MB"
#set ytics nomirror
set y2tics 10000

set grid
set style data linespoints

plot "$INPUT" using 1:2 title "%CPU" with lines, \
           "" using 1:(\$3/1000) title "Virtual Memory"  with lines axes x1y2, \
           "" using 1:(\$4/1000) title "Resident Memory" with lines axes x1y2
  
#set xrange[GPVAL_DATA_X_MIN:GPVAL_DATA_X_MAX]

#set y2range[GPVAL_DATA_Y2_MIN:GPVAL_DATA_Y2_MAX]

set terminal pdf
set output "$OUTPUT"

replot
EOF