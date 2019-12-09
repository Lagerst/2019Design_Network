from scapy.base_classes import *
from scapy.config import *
from scapy.dadict import *
from scapy.data import *
from scapy.error import *
from scapy.themes import *
from scapy.arch import *
from scapy.plist import *
from scapy.fields import *
from scapy.packet import *
from scapy.asn1fields import *
from scapy.asn1packet import *
from scapy.utils import *
from scapy.route import *
from scapy.sendrecv import *
from scapy.sessions import *
from scapy.supersocket import *
from scapy.volatile import *
from scapy.as_resolvers import *
from scapy.ansmachine import *
from scapy.automaton import *
from scapy.autorun import *
from scapy.main import *
from scapy.consts import *
from scapy.compat import raw  # noqa: F401
from scapy.layers.all import *
from scapy.asn1.asn1 import *
from scapy.asn1.ber import *
from scapy.asn1.mib import *
from scapy.pipetool import *
from scapy.scapypipes import *
import scapy_http.http as http

if conf.ipv6_enabled:  # noqa: F405
    from scapy.utils6 import *  # noqa: F401
    from scapy.route6 import *  # noqa: F401

import re
import time
from pyecharts import Pie, Page, Bar, Line
import webbrowser
import tkinter

v2 = [0, 0]
v1 = [0, 0, 0, 0]
record = [0, 0, 0, 0, 0]
timerecord = [[0], [0], [0], [0], [0]]
timesingle = [[0], [0], [0], [0], [0]]
timetime = [0, 0, 0, 0, 0]
tr = []
dict = {}
Round = 3
breaktime = 0.5
Cnt = 1000
attr = ['JD', 'bilibili', 'CSDN', 'Taobao', 'Tencent QQ']


# IP mapping
def make_link_ip():
    dict['58.205.217.1'] = 0  # jd
    dict['120.52.148.118'] = 0
    dict['111.231.211.246'] = 1  # bilibili
    dict['119.27.176.150'] = 1
    dict['120.24.248.50'] = 1
    dict['140.143.82.138'] = 1
    dict['111.231.212.88'] = 1
    dict['120.92.162.180'] = 1
    dict['47.95.164.112'] = 2  # CSDN
    dict['58.205.221.214'] = 3  # Taobao
    dict['58.205.221.253'] = 3
    dict['140.205.94.189'] = 3
    dict['140.205.94.193'] = 3
    dict['203.119.215.107'] = 3
    # dict['121.51']=4 Tencent QQ
    # dict['210.41']=4
    # dict['111.231']=1


def main():
    print(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
    tr.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))

    for t in range(0, Round):

        # 嗅探抓包
        wlan = sniff(iface='WLAN', count=Cnt)
        s = str(wlan)
        print(wlan)
        print(wlan.show())
        # wrpcap('packet.cap', wlan)

        # 提取数据
        v3 = re.findall(r"\d+\.?\d*", s)
        for i in range(0, len(v3)):
            v1[i] += int(v3[i])
        for i in range(0, len(wlan)):
            try:
                if 'IPv6' in wlan[i]:
                    v2[1] += 1
                else:
                    v2[0] += 1
                if wlan[i].payload.dst in dict.keys():
                    record[dict[wlan[i].payload.dst]] += 1
                elif wlan[i].payload.src in dict.keys():
                    record[dict[wlan[i].payload.src]] += 1
                # else:
                #    record[0] += 1
                elif ('121.51' in wlan[i].payload.dst) or ('121.51' in wlan[i].payload.src) or \
                        ('210.41' in wlan[i].payload.dst) or ('210.41' in wlan[i].payload.src):
                    record[4] += 1
                elif ('111.231' in wlan[i].payload.dst) or ('111.231' in wlan[i].payload.src):
                    record[1] += 1
                print(wlan[i].show())
            except:
                pass
            # print(hexdump(p))

        # 数据处理
        for i in range(0, len(timerecord)):
            timerecord[i].append(record[i])
            timesingle[i].append(record[i] - timerecord[i][t])
            timetime[i] += min(record[i] - timerecord[i][t], 1)
        tr.append(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time())))
        print('this is the %dth round, sleeping for %f second(s).' % (t + 1, breaktime))
        time.sleep(breaktime)

    # For Debug Use
    print(timerecord)
    print(tr)
    # 作图
    global attr
    page = Page()
    bar = Bar('报文活跃柱状图')
    bar.add('按抽样时间分类',
            attr,
            timetime,
            # is_convert=True,
            is_more_utils=True  # 设置最右侧工具栏
            )
    page.add_chart(bar)
    bar = Bar('报文请求-时间柱状图')
    for i in range(0, len(timerecord)):
        bar.add(attr[i],
                tr[1:],
                timesingle[i][1:],
                is_datazoom_show=True,
                # is_convert=True,
                is_more_utils=True  # 设置最右侧工具栏
                )
    page.add_chart(bar)
    line = Line("访问报文数量-时间折线图")
    for i in range(0, len(timerecord)):
        line.add(
            attr[i],
            tr,
            timerecord[i],
            is_datazoom_show=True,
            is_fill=True,
            line_opacity=0.2,
            area_opacity=0.4
        )
    page.add_chart(line)
    pie = Pie('网络-IP类型饼状图', title_pos='left')
    attr = ['TCP', 'UDP', 'ICMP', 'Other']
    pie.add(
        '', attr, v1,  # ''：图例名（不使用图例）
        radius=[50, 75],  # 环形内外圆的半径
        is_label_show=True,  # 是否显示标签
        label_text_color=None,  # 标签颜色
        legend_orient='vertical',  # 图例垂直
        legend_pos='right'
    )
    attr = ['IP', 'IPv6']
    pie.add(
        '', attr, v2,
        radius=[15, 35],
        is_label_show=True,
        label_text_color=None,
        legend_orient='vertical',
        legend_pos='right'
    )
    page.add_chart(pie)

    # 保存
    page.render('./page.html')

    # 打开
    chromepath = 'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
    webbrowser.register('chrome', None, webbrowser.BackgroundBrowser(chromepath))
    webbrowser.get('chrome').open('page.html')


def GUI():
    def func1():
        win1 = tkinter.Tk()
        win1.title("Existing Protocols and Parameters")
        text = tkinter.Text(win1, width=50, height=20)
        text.pack()
        str = 'Round=' + repr(Round) + '\nCnt=' + repr(Cnt) + '\nBreaktime=' + repr(breaktime)
        str += '''\ndict['121.51']=Tencent QQ\ndict['210.41']=Tencent QQ\ndict['111.231']=bilibili'''
        for key in dict:
            str += '\ndict[' + key + ']=' + attr[dict[key]]
        text.insert(tkinter.INSERT, str)
        win1.mainloop()

    def func2():
        def funcadd():
            dict[entry1.get()] = int(entry2.get())

        win1 = tkinter.Tk()
        win1.title("Add Protocol")
        tkinter.Label(win1, text="IP Address").grid(row=0)
        tkinter.Label(win1, text="Value").grid(row=1)
        e = tkinter.Variable()
        e2 = tkinter.Variable()
        entry1 = tkinter.Entry(win1, textvariable=e)
        entry2 = tkinter.Entry(win1, textvariable=e2)
        entry1.grid(row=0, column=1)
        entry2.grid(row=1, column=1)
        button5 = tkinter.Button(win1, text="Add", command=funcadd, width=20, height=1)
        button5.grid(row=2)
        win1.mainloop()

    def func3():
        def funcadd():
            global Round, Cnt, breaktime
            Round = int(entry1.get())
            Cnt = int(entry2.get())
            breaktime = float(entry3.get())

        win1 = tkinter.Tk()
        win1.title("Set Parameters")
        tkinter.Label(win1, text="Round").grid(row=0)
        tkinter.Label(win1, text="Cnt").grid(row=1)
        tkinter.Label(win1, text="Breaktime").grid(row=2)
        e = tkinter.Variable()
        e2 = tkinter.Variable()
        e3 = tkinter.Variable()
        entry1 = tkinter.Entry(win1, textvariable=e)
        entry2 = tkinter.Entry(win1, textvariable=e2)
        entry3 = tkinter.Entry(win1, textvariable=e3)
        entry1.grid(row=0, column=1)
        entry2.grid(row=1, column=1)
        entry3.grid(row=2, column=1)
        button6 = tkinter.Button(win1, text="Add", command=funcadd, width=20, height=1)
        button6.grid(row=3)
        win1.mainloop()

    def func4():
        main()

    make_link_ip()

    win = tkinter.Tk()
    win.title("基于Scapy和PyEcharts的可视化网络嗅探监督系统")
    win.geometry("600x400+200+50")

    button1 = tkinter.Button(win, text="Existing Protocols", command=func1, width=20, height=3)
    button1.pack()

    button2 = tkinter.Button(win, text="Add Protocol", command=func2, width=20, height=3)
    button2.pack()

    button3 = tkinter.Button(win, text="Set Parameters", command=func3, width=20, height=3)
    button3.pack()

    button4 = tkinter.Button(win, text="Begin", command=func4, width=20, height=3)
    button4.pack()

    win.mainloop()


GUI()
