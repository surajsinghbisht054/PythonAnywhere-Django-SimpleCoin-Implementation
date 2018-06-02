# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from pcodes import all_formats, all_lexers, codes
# Create your views here.


def mainindex(request):
    return render(request, 'index.html')



def dcode(requests):
    if requests.method =='POST':
        c = requests.POST['code'] or 'import python'
        d = requests.POST['lexer'] or 'python'
        e = requests.POST['style'] or 'colorful'

        html = codes(c, lexer=d, style=e)
        context = {
            'lexers': all_lexers,               # All Lexers name
            'styles': all_formats,              # All Formats
            'lexer' : requests.POST['lexer'],    # selected Style
            'preview':html,   # preview
            'code':requests.POST['code'],      # code
            'html':html       # html
        }
    
    else:
        html = codes('import python', lexer='python', style='colorful')
        context = {
            'lexers': all_lexers, # All Lexers name
            'styles': all_formats, # All Formats
            'lexer':'Python',         # Selected Lexer
            'style':'colorful',         #selected Style
            'preview':html,       # preview
            'code':'import python',          # code
            'html':html           # html
        }
    return render(requests, 'dcode/index.html', context)