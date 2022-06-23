from asyncio.windows_events import NULL
import enum
from tkinter.tix import COLUMN
from turtle import st
import xml.etree.ElementTree as elt
import os
import glob
from os.path import isfile, join
import xlsxwriter
from tkinter.tix import COLUMN
from cgitb import text
from email import header
from fileinput import filename
from sre_parse import State
import tkinter as tk
from tkinter import *
from tkinter import filedialog
from numpy import size
from subprocess import call
import time

class vulnData:
    def __init__(self):
        self.cat1 = []
        self.cat2 = []
        self.cat3 = []

def browseFiles():
    browseFiles.filePath = filedialog.askdirectory(initialdir = "/", title = "Choose a file")
    fileReadback.config(state = NORMAL)
    fileReadback.insert(1.0, browseFiles.filePath)
    fileReadback.config(state = DISABLED)

def getUniques():
    
    folder = glob.glob(browseFiles.filePath + "\\*.ckl")
    stigList = {}
    tree = elt.ElementTree()

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

            if status.text == "Not_Reviewed":
                errorWindow = tk.Tk()
                errorWindow.title("Error!")
                errorLabel = Label(errorWindow, text = "Error! \n" + os.path.basename(checklists) + "\n has unreviewed checks.\n Please make sure all checks are reviewed and try again.")
                errorLabel.pack(side="top", fill="x",pady=10)
                acceptButton = Button(errorWindow, text = "Okay", command = lambda:[errorWindow.destroy(), window.destroy(), quit()], height = 2, width = 15)
                acceptButton.pack(side="bottom",pady=10)
                errorWindow.mainloop()
                
                
            elif status.text == "Open":

                #Grabbing the information in "STIG_DATA" tag
                stigData = cklData.findall("STIG_DATA")

                #Looking at the info in "STIG_DATA" tags
                severity = ""
                vulnNum = ""

                for data in stigData:
                    
                    if data[0].text == "Severity":
                        severity = data[1].text.strip("\n")
                    elif data[0].text == "Vuln_Num":
                        vulnNum = data[1].text.strip("\n")
                    
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

    window.destroy()


window = Tk()
window.title("Finding Tracker")
window.geometry("500x200")

#Header that tells the user what to do
header = Label(window, text = "Select a directory of checklists to process.", font = (("Calibri"), 15))
header.place(anchor=CENTER, relx = .5, rely = .1)

#Button to open file explorer
browseFilesButton = Button(window, text = "Browse Files", command = browseFiles, height = 2, width = 20)
browseFilesButton.place(anchor=CENTER, relx = .20, rely = .33)

#Text box that reads back the directory selected
fileReadback = Text(height = 2, width = 30, state = DISABLED)
fileReadback.place(anchor = CENTER, relx = .65, rely = .33)

#Button to get all the inputs and begin processing
startButton = Button(window, text = "Start", height = 3, width = 30, command = getUniques)
startButton.place(anchor = CENTER, relx = .5, rely = .66)

window.mainloop()

outFile = open("testFile.txt", "w")


# Input Files:
# Host001_A10NetworksADCNDM_V1R1
# Host001_AdobeAcrobatReaderDC_V2R1
# Host001_MSWord2013_V1R6
# Host001_RHEL8_V1R6
# Host001_zOSCatalogSolutions_V6R4
# Host002_A10NetworksADCNDM_V1R1
# Host002_AdobeAcrobatReaderDC_V2R1
# Host003_AdobeAcrobatReaderDC_V2R1

# Output:

# A10 Networks ADC NDM Security Technical Implementation Guide
# Total Unique Cat 1s: 2 proof['V-68051', 'V-68093']
# Total Unique Cat 2s: 3 proof['V-68053', 'V-68055', 'V-68037']
# Total Unique Cat 3s: 0 proof[]

# Adobe Acrobat Reader DC Continuous Track Security Technical Implementation Guide
# Total Unique Cat 1s: 1 proof['V-213192']
# Total Unique Cat 2s: 7 proof['V-213168', 'V-213169', 'V-213170', 'V-213181', 'V-213193', 
# 'V-213173', 'V-213184']
# Total Unique Cat 3s: 2 proof['V-213187', 'V-213176']

# Microsoft Word 2013 STIG
# Total Unique Cat 1s: 0 proof[]
# Total Unique Cat 2s: 4 proof['V-26615', 'V-26616', 'V-26617', 'V-26648']
# Total Unique Cat 3s: 0 proof[]

# Red Hat Enterprise Linux 8 Security Technical Implementation Guide
# Total Unique Cat 1s: 4 proof['V-230223', 'V-230234', 'V-230235', 'V-230533']
# Total Unique Cat 2s: 20 proof['V-230226', 'V-230228', 'V-230229', 'V-230349', 'V-230367', 'V-230369',
# 'V-230370', 'V-230371', 'V-230372', 'V-230390', 'V-230392', 'V-230393', 'V-230419', 'V-230425', 
# 'V-230426', 'V-230427', 'V-230429', 'V-230430', 'V-230431', 'V-230472'] 
# Total Unique Cat 3s: 6 proof['V-230292', 'V-230293', 'V-230294', 'V-230346', 'V-230350', 'V-230470']

# z/OS Catalog Solutions for RACF STIG
# Total Unique Cat 1s: 0 proof[]
# Total Unique Cat 2s: 0 proof[]
# Total Unique Cat 3s: 0 proof[]
                
                


                
                        