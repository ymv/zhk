ZHK
===

Find processes, whose executable match regex and memory consumption is above threshold. Then SIGKILL them

See --help for options

Example
-------

<code>
python zhk.py '.*zeit.*' -t 5 --daemon zhk.pid --log zhk.log
</code>

Why?
----

/usr/bin/zeitgeist-daemon sometimes decides to consume most of memory on my feeble machine. Making script to kill it was faster than finding why it does this.
