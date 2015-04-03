set terminal png size 700,550 enhanced font "Helvetica,20"
set output "memory.png"
set xlabel "Time in seconds"
set ylabel "Memory usage in kB"
plot "vmdata.log" using 1:2 with lines title "VmData", \
     "vmrss.log" using 1:2 with lines title "VmRSS"

