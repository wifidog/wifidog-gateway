
$Header$

This file contains some small notes on developing the WiFiDog application.

The application's home page is http://www.ilesansfil.org/wiki/WiFiDog
The application's sourceforge page is http://sourceforge.net/projects/wifidog/

As a developer, you must subscribe to sourceforge as a "developer" under WiFiDog, as well as subscribe to the WiFiDog mailing list located at http://isf.waglo.com/mailman/listinfo/wifidog_isf.waglo.com

SOURCE CODE:
	- Please do not contribute unless you agree with the GPL license and are contributing your portion under that license.  See the included LICENSE.txt
	- Please respect the intellectual property of others.  You are not allowed to taint WiFiDog by including source code from projects that do not allow so.
	- Keep in mind that this application will run on extremely simple embedded devices.  The binary size needs to be small, the dependencies absolutely minimal, and the memory footprint negligible.
	- Always place the CVS "Header" macro at the top of every file
	- Since this is a collaborative project, please aim for clearness instead of cleverness when faced with a choice.
	- If you must use some cleverness, please add appropriate clear comments.
	- Please re-indent your code before committing to CVS - see the "Formatting Your Source Code" section in the GNU Coding Standards at http://www.gnu.org/prep/standards_toc.html - the entire document makes a good reading if you haven't read it before.  Also see the "indent" program.
	- Before writing any brand-new large chunks of code, make sure it's logic has been discussed with the other team of developers or included in the design stage.

DOCUMENTATION:
	- Please use DoxyGen-style comments (see http://www.doxygen.org/ for details) for source code documentation.
	- Please use DocBook-SGML documentation for user documentation.  This will make it easy to export documentation in multiple formats.  Otherwise submit your documentation in plaintext format to someone who will change it to DocBook.
	- Please thoroughly-comment non-clear sections in your code.
