
$Id$


This file contains some small notes on developing the WiFiDog application.


The application's GitHub page is:
	https://github.com/wifidog/

As a developer, you should subscribe to the GitHub project:
	https://github.com/wifidog/wifidog-gateway/subscription

Main development is happening on GitHub, but the project website has lots of useful information
and some remaining tickets:
	http://dev.wifidog.org/

There is also a (somewhat unused) SourceForge page:
	http://sourceforge.net/projects/wifidog/

WifiDog uses semantic versioning:
	http://semver.org/


CONTRIBUTION CHECKLIST:
A quick checklist for new contributors. See below for details.
	- Indent your code properly
	- Document your code and follow DoxyGen style
	- Your pull request must include an update to the NEWS file
	- Fix all compiler warnings

Once your patch is good to go, submit a pull request on GitHub:
	https://github.com/wifidog/wifidog-gateway/pulls

If you're having any questions, file an issue on GitHub and add the "Question"
label:
	https://github.com/wifidog/wifidog-gateway/issues/new

SOURCE CODE:
	- Please do not contribute unless you agree with the GPL license and are contributing your portion under that license.  See the included LICENSE.txt
	- Please respect the intellectual property of others.  You are not allowed to taint WiFiDog by including source code from projects that do not allow so.
	- Keep in mind that this application will run on extremely simple embedded devices.  The binary size needs to be small, the dependencies absolutely minimal, and the memory footprint negligible.
	- Since this is a collaborative project, please aim for clearness instead of cleverness when faced with a choice.
	- If you must use some cleverness, please add appropriate clear comments.
	- Please format your code properly before submitting a patch or a pull request. In general, we use 4 tabs instead of spaces with a maximum
	  line length of 120. In VIM, use these settings:
		set expandtab
		set shiftwidth=4
		set softtabstop=4
		set tabstop=4
	  The complete code style is defined by the following GNU indent call:
		indent --linux-style --no-tabs --indent-level 4 --line-length 120 --procnames-start-lines
	- Do not introduce compiler warnings. If the compiler warning is indeed harmless, disable it with the appropriate -Wno- flag in Makefile.am
	- Before writing any brand-new large chunks of code, make sure it's logic has been discussed with the other team of developers or included in the design stage.


MEMORY ALLOCATION IN SOURCE CODE:
	- Safe versions of C functions that allocate memory (safe_malloc, safe_asprintf, etc..) have been created in safe.c . You must use them instead of the original functions.
	- If you need to use a memory-allocating C function that does not have a safe version in safe.c, create the safe wrapper first (following the template of the others) and use that instead of calling the original.


DOCUMENTATION:
	- Please use DoxyGen-style comments (see http://www.doxygen.org/ for details) for source code documentation.
	- Please use DocBook-SGML documentation for user documentation.  This will make it easy to export documentation in multiple formats.  Otherwise submit your documentation in plaintext format to someone who will change it to DocBook.
	- Please thoroughly-comment non-clear sections in your code.
	- Remember that commit messages and pull request descriptions also serve as a form of documentation.

