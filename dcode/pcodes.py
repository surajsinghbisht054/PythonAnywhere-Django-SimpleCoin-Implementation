#!/usr/bin/python

from pygments.lexers import get_all_lexers
from pygments.styles import get_all_styles
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import HtmlFormatter

all_lexers = []
for i in get_all_lexers():
	i=i[0]
	if (" " not in i) and ("+" not in i) and ("(" not in i) and ("-" not in i) and ("/" not in i):
		all_lexers.append(i) 
all_lexers.sort()
all_formats =[i for i in get_all_styles()]
all_formats.sort()
def cool(code):
	tmp = '<div style="border-radius: 4px;border: solid #4286f4;background-color: whitesmoke;"> {} <div style="background-color: lawngreen;"><object align="right">&hearts;Dcode&hearts;  </object></div></div>'
	return tmp.format(code)

def codes(codes, lexer='html', style='colorful'):
	beauti_looks = "overflow:auto; width:auto; background-color:#f6f8fa; border-radius: 3px;font-family: Courier,monospace;"
	#beauti_looks+= 'border:solid;border-width:.1em .1em .1em .1em;padding:.2em .6em;'
	formatter = HtmlFormatter(style=style, 
				noclasses=True,
				linenos='table',
				prestyles='',
				cssstyles = beauti_looks,
				)
	#formatter.cssstyles = 'background:red;'
	#formatter.prestyle = 'boder:solid;'
	output = highlight(codes, get_lexer_by_name(lexer), formatter)
	return cool(output)

zen = '''
The Zen of Python, by Tim Peters

Beautiful is better than ugly.
Explicit is better than implicit.
Simple is better than complex.
Complex is better than complicated.
Flat is better than nested.
Sparse is better than dense.
Readability counts.
Special cases aren't special enough to break the rules.
Although practicality beats purity.
Errors should never pass silently.
Unless explicitly silenced.
In the face of ambiguity, refuse the temptation to guess.
There should be one-- and preferably only one --obvious way to do it.
Although that way may not be obvious at first unless you're Dutch.
Now is better than never.
Although never is often better than *right* now.
If the implementation is hard to explain, it's a bad idea.
If the implementation is easy to explain, it may be a good idea.
Namespaces are one honking great idea -- let's do more of those!


'''


if __name__=='__main__':
	print all_lexers
	print all_formats
	f = open('check.html', 'w')
	f.write(codes(zen))
	f.close()
