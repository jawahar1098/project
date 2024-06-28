
from pymongo import MongoClient
import pymongo


client = MongoClient('mongodb://localhost:27017/') 


class video_analysis():
    def __init__(self) -> None:
        self.db=client['video_analysis']
        self.case = self.db['cases']
        self.filemanager = self.db['filemanager']
        self.face_log=self.db['face_log']
        self.cluster_log=self.db['face_clusters']
        self.cluster_main_log=self.db['face_clusters_main']
        self.numplate_result =self.db["detected_result"]
        self.numplate_clusters=self.db['numplate_clusters']
        self.reverse_search="outputs/ReverseSearchImage"
        return None



    
    




    





