import csv
import hashlib
import os

import pandas as pd
# from pandas.core.indexes import category
from tastypie import bundle

from dojo.models import Finding, Notes, Note_Type, User


class TempParser(object):
    # def __init__(self, filename, test):
    #     normalized_findings = self.normalize_findings(filename)
    #     self.ingest_findings(normalized_findings, test)

    def __init__(self, filename, test):
        dupes = dict()
        notes1 = dict()
        notes2 = dict()
        notes3 = dict()
        notes4 = dict()
        self.items = ()
        self.note1 = ()
        self.note2 = ()
        self.note5 = ()
        self.note6 = ()

        # df = pd.read_csv(filename, header=0, error_bad_lines=False)
        # for i, row in df.iterrows():
        #     finding_id = df.loc[i, 'finding_id']
        #     issue_id = df.loc[i, 'description']
        #     print(finding_id)
        #     print(issue_id)

        if filename is None:
            self.items = ()
            return

        df = pd.read_csv(filename, header=0)

        for i, row in df.iterrows():
            # Vulnerability Name,Vulnerability ID,Category,Rule Name,Severity,Status,Number of Events,First Seen,Last Seen,Application Name,Application ID,Application Code,CWE ID,Request Method,Request Port,Request Protocol,Request Version,Request URI,Request Qs,Request Body
            # cwe = self.format_cwe(df.ix[i, 'finding_id'])
            cwe = df.loc[i, 'cwe']
            title = df.loc[i, 'title']
            description = df.loc[i, 'description']
            sev = df.loc[i, 'severity']
            line = df.loc[i, 'line_number']
            issue_id = df.loc[i, 'issue_id']
            use_case_note = df.loc[i, 'Use_Case']
            vul_influence_note = df.loc[i, 'Vulnerability_Influence']
            resolution_note = df.loc[i, 'Resolution']
            sourcefilepath = df.loc[i, 'sourcefilepath']
            sourcefile = df.loc[i, 'sourcefile']
            mitigation = df.loc[i, 'mitigation']
            impact = df.loc[i, 'impact']
            WSO2_resolution = df.loc[i, 'WSO2_resolution']

            # dupe_key = hashlib.md5(str(cwe).encode('utf-8') + title.encode('utf-8')).hexdigest()
            # try:
            dupe_key = sev + str(cwe) + str(line) + str(sourcefile) + str(sourcefilepath) + str(title) + str(issue_id)
            # except:
            #     dupe_key = sev + flaw.attrib['cweid'] + flaw.attrib['module'] + flaw.attrib['type'] + flaw.attrib[
            #         'issueid']
            if dupe_key in dupes:
                finding = dupes[dupe_key]
                if finding.description:
                    finding.description = finding.description + "\nVulnerability ID: " + \
                                          df.loc[i, 'mitigation']
                # self.process_endpoints(finding, df, i)
                dupes[dupe_key] = finding
            else:
                dupes[dupe_key] = True

                finding = Finding(title=title,
                                  cwe=int(cwe),
                                  test=test,
                                  active=False,
                                  verified=False,
                                  severity=sev,
                                  static_finding=True,
                                  line_number=line,
                                  file_path=sourcefilepath+sourcefile,
                                  line=line,
                                  sourcefile=sourcefile,
                                  description=description,
                                  numerical_severity=Finding.
                                  get_numerical_severity(sev),
                                  mitigation=mitigation,
                                  impact=impact,
                                  url='N/A')
            # use_case_note=use_case_note,
            # vul_influence_note=vul_influence_note,
            # resolution_note=resolution_note,
            # numerical_severity=Finding.get_numerical_severity(
            #     severity),
            # mitigation=mitigation,
            # impact=impact,
            # references=references,
            # url='N/A',
            # dynamic_finding=False)

            note3 = Notes(entry=use_case_note, note_type=Note_Type(id=2), author=User.objects.all().first())
            note4 = Notes(entry=vul_influence_note, note_type=Note_Type(id=3), author=User.objects.all().first())
            note6 = Notes(entry=WSO2_resolution, note_type=Note_Type(id=1), author=User.objects.all().first())
            note7 = Notes(entry=resolution_note, note_type=Note_Type(id=4), author=User.objects.all().first())
            note3.save()
            note4.save()
            note6.save()
            note7.save()

            # finding.notes.add(note1)
            # finding.notes.add(note2)
            dupes[dupe_key] = finding
            notes1[dupe_key] = note3
            notes2[dupe_key] = note4
            notes3[dupe_key] = note6
            notes4[dupe_key] = note7

            # finding.notes.add(note1)
            # finding.notes.add(note2)
            dupes[dupe_key] = finding
            notes1[dupe_key] = note3
            notes2[dupe_key] = note4
            notes3[dupe_key] = note6
            notes4[dupe_key] = note7

                # self.process_endpoints(finding, df, i)

        self.items = list(dupes.values())
        self.note1 = list(notes1.values())
        self.note2 = list(notes2.values())
        self.note5 = list(notes3.values())
        self.note6 = list(notes4.values())
        print(self.items)


        # normalized_findings = self.items
        # self.ingest_findings(normalized_findings, test)

        # if filename is None:
        #     self.items = ()
        #     print(self.items)
        #     return
        # content = open(filename.temporary_file_path(), "rb").read().replace("\r".encode(), "\n".encode())
        # # content = re.sub("\"(.*?)\n(.*?)\"", "\"\1\2\"", content)
        # # content = re.sub("(?<=\")\n", "\\\\n", content)
        # with open("%s-filtered" % filename.temporary_file_path(), "wb") as out:
        #     out.write(content)
        #     out.close()

        # print(b'content')

        # with open("%s-filtered" % filename.temporary_file_path(), "rb") as scan_file:
        #     reader = csv.reader(scan_file,
        #                         lineterminator="\n",
        #                         quoting=csv.QUOTE_ALL)
        #     dupes = {}
        #     first = True
        #     for row in reader:
        #         if first:
        #             heading = row
        #             first = False
        #             continue
        #
        #         dat = {}
        #         endpoint = None
        #         for h in ["severity", "endpoint",
        #                   "title", "description",
        #                   "mitigation", "references",
        #                   "impact", "plugin_output", "port"]:
        #             dat[h] = None
        #
        #         for i, var in enumerate(row):
        #             if not var:
        #                 continue
        #
        #             var = re.sub("(\A(\\n)+|(\\n)+\Z|\\r)", "", var)
        #             var = re.sub("(\\n)+", "\n", var)
        #
        #             if heading[i] == "CVE":
        #                 if re.search("(CVE|CWE)", var) is None:
        #                     var = "CVE-%s" % str(var)
        #                 if dat['references'] is not None:
        #                     dat['references'] = var + "\n" + dat['references']
        #                 else:
        #                     dat['references'] = var + "\n"
        #             elif heading[i] == "Risk":
        #                 if re.match("None", var) or not var:
        #                     dat['severity'] = "Info"
        #                 else:
        #                     dat['severity'] = var
        #             elif heading[i] == "Host":
        #                 dat['endpoint'] = var
        #                 endpoint = Endpoint(host=var)
        #             elif heading[i] == "Port":
        #                 if var != "None":
        #                     if dat['description'] is not None:
        #                         dat['description'] = "Ports:"
        #                         + var + "\n" + dat['description']
        #                     else:
        #                         dat['description'] = "Ports:" + var + "\n"
        #
        #                     dat['port'] = var
        #                     endpoint.host += ":" + var
        #                 else:
        #                     dat['port'] = 'n/a'
        #
        #             elif heading[i] == "Name":
        #                 dat['title'] = var
        #             elif heading[i] == "Synopsis":
        #                 dat['description'] = var
        #             elif heading[i] == "Description":
        #                 dat['impact'] = var
        #             elif heading[i] == "Solution":
        #                 dat['mitigation'] = var
        #             elif heading[i] == "See Also":
        #                 if dat['references'] is not None:
        #                     dat['references'] += var
        #                 else:
        #                     dat['references'] = var
        #             elif heading[i] == "Plugin Output":
        #                 dat['plugin_output'] = "\nPlugin output(" + \
        #                                        dat['endpoint'] + \
        #                                        "):\n```\n" + str(var) + \
        #                                        "\n```\n"
        #
        #         if not dat['severity']:
        #             dat['severity'] = "Info"
        #         if not dat['title']:
        #             continue
        #
        #         dupe_key = dat['severity'] + dat['title']
        #
        #         if dupe_key in dupes:
        #             find = dupes[dupe_key]
        #             if dat['plugin_output'] is not None:
        #                 find.description += dat['plugin_output']
        #         else:
        #             if dat['plugin_output'] is not None:
        #                 dat['description'] = dat['description'] + \
        #                                      dat['plugin_output']
        #             find = Finding(title=dat['title'],
        #                            test=test,
        #                            active=False,
        #                            verified=False, description=dat['description'],
        #                            severity=dat['severity'],
        #                            numerical_severity=Finding.get_numerical_severity(dat['severity']),
        #                            mitigation=dat['mitigation'] if dat['mitigation'] is not None else 'N/A',
        #                            impact=dat['impact'],
        #                            references=dat['references'],
        #                            url=dat['endpoint'])
        #
        #             find.unsaved_endpoints = list()
        #             dupes[dupe_key] = find
        #
        #         if endpoint:
        #             find.unsaved_endpoints.append(endpoint)
        # os.unlink(filename.temporary_file_path())
        # os.unlink("%s-filtered" % filename.temporary_file_path())
        # self.items = list(dupes.values())