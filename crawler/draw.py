# -*- coding: utf-8 -*-
#
# draw.py - helper module of pyCrawler to draw map from hosts using pygraphviz
#
# Copyright (c) 2019 Lars Bergmann
#
# GNU GENERAL PUBLIC LICENSE
#    Version 3, 29 June 2007
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# draw map from hosts
import pygraphviz


def draw_graph(host_map, filename='host_map.png', draw_format='png',
               prog='fdp'):
    '''draw graph from host_map using pygraphviz
    '''
    graph = pygraphviz.AGraph(directed=True)
    for from_host, to_host in host_map:
        graph.add_node(from_host)
        graph.add_node(to_host)
        graph.add_edge(from_host, to_host)
    graph.draw(filename, format=draw_format, prog=prog)
