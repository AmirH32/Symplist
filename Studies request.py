import requests, json
import xml.etree.ElementTree as ET


IDs = []
query = input("Enter what you want to search pubmed:")
Response = requests.get(f"https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi?db=pubmed&term=science[journal]+AND+{query}")
response_xml_as_string = Response.content
responseXml = ET.fromstring(response_xml_as_string)
testId = responseXml.find('IdList')
for i in testId:
    IDs.append(i.text)

for i in IDs:
    Response = requests.get(f"https://www.ncbi.nlm.nih.gov/pmc/utils/idconv/v1.0?tool=my_tool&email=amirhassanali2610@gmail.com.com&ids={i}")
    response_xml_as_string = Response.content
    responseXml = ET.fromstring(response_xml_as_string)
    try:
        pmcid = responseXml[1].attrib['pmcid']
        print(pmcid)
        response = requests.get(f"https://www.ncbi.nlm.nih.gov/research/bionlp/RESTful/pmcoa.cgi/BioC_json/{'PMC9127978'}/unicode").json()
        print(response)
        for i in response['documents'][0]['passages']:
            print(i['text'])

    except:
        print("This search has no pmcid")


