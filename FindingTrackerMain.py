from asyncio.windows_events import NULL
import enum
from tkinter.tix import COLUMN
from turtle import st
import xml.etree.ElementTree as elt
import os
import glob
from os.path import isfile, join
import xlsxwriter

class vulnData:
    def __init__(self):
        self.cat1 = []
        self.cat2 = []
        self.cat3 = []
        pass



stigList = {}

outFile = open("testFile.txt", "w")

tree = elt.ElementTree()

folder = glob.glob("C:\\Users\\JLMcB\\Documents\\TestingChecklists\\*.ckl")


for checklists in folder:

    tree.parse(checklists)

    root = tree.findall("STIGS/iSTIG/STIG_INFO")

    vulndata = vulnData()

    for stigData in root:

        stigInfo = stigData.findall("SI_DATA")

        for data in stigData:
            if data[0].text == "title":
                stigTitle = data[1].text
                if (len(stigList) == 0 or stigTitle not in stigList): 
                    stigList.update({stigTitle : vulndata})
                else:
                    vulndata = stigList[stigTitle]
                break
                

    root = tree.findall("STIGS/iSTIG/VULN")

    for cklData in root:

        status = cklData.find("STATUS")

        if status.text == "Open":

			#Grabbing the information in "STIG_DATA" tag
            stigData = cklData.findall("STIG_DATA")

			#Looking at the info in "STIG_DATA" tags
            severity = ""
            vulnNum = ""

            for data in stigData:
                
				#Switch statement to get the information within fields that have data we want Vuln_Num/Rule_Title/Severity
                # match data[0].text:
                #     case "Vuln_Num":
                #         vulnNumber = data[1].text.strip("\n")
                #         continue

                #     case "Severity":
                #         severity = data[1].text.strip("\n")
                #         continue
                
                if data[0].text == "Severity":
                    severity = data[1].text.strip("\n")
                    #print(f"sev {severity}")
                elif data[0].text == "Vuln_Num":
                    vulnNum = data[1].text.strip("\n")
                    #print(f"vulnNum {vulnNum}")
                
            print(f"vuln {vulnNum} sev {severity}")
            if severity != "" and vulnNum != "":
                match severity:
                    case "low":
                        if vulnNum not in vulndata.cat3:
                            vulndata.cat3.append(vulnNum)
                    case "medium":
                        if vulnNum not in vulndata.cat2:
                            vulndata.cat2.append(vulnNum)
                    case "high":
                        if vulnNum not in vulndata.cat1:
                            vulndata.cat1.append(vulnNum)

for key, value in stigList.items():
    print(key)
    print(f"Total Unique Cat 1s: {len(value.cat1)} proof{value.cat1}")
    print(f"Total Unique Cat 2s: {len(value.cat2)} proof{value.cat2}")
    print(f"Total Unique Cat 3s: {len(value.cat3)} proof{value.cat3}")
                
                


                
                        