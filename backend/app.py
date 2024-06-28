from flask import Flask, request, jsonify
import os
import hashlib
import time
from datetime import datetime
from loguru import logger
from bson import ObjectId
from flask import Flask, request, jsonify
from bson import ObjectId

from pymongo import MongoClient
from bson.json_util import dumps
import json
from bson.objectid import ObjectId
from bson import json_util
from MongoClient import video_analysis
mongo_conn=video_analysis()

app = Flask(__name__)

def calculate_file_hash(filePath, hash_algorithm='sha256'):
    try:
        hasher = hashlib.new(hash_algorithm)
        with open(filePath, 'rb') as file:
            while True:
                data = file.read(65536)  # Read the file in 64KB chunks
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()
    except Exception as e:
        print("error in hash", e)
        
        
def calculate_string_hash(input_string, hash_algorithm='sha256'):
    try:
        # Check if input_string is actually a string
        if not isinstance(input_string, str):
            raise TypeError("Input must be a string")

        # Check if the specified hash algorithm is supported
        if hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")

        # Create a new hash object
        hasher = hashlib.new(hash_algorithm)
        # Update the hash object with the encoded string
        hasher.update(input_string.encode('utf-8'))
        # Return the hexadecimal digest of the hash
        return hasher.hexdigest()
    except TypeError as te:
        print("Type error in hash calculation:", te)
    except ValueError as ve:
        print("Value error in hash calculation:", ve)
    except Exception as e:
        print("Unexpected error in hash calculation:", e)
    return None

@app.route('/video_upload', methods=['POST'])
def video_upload():
    caseId = request.form.get('caseId')
    videoFiles = request.files.getlist('videoFiles')
    facialAnalysis = request.form.get('facialAnalysis')
    numberPlateAnalysis = request.form.get('numberPlateAnalysis')
    
    if not caseId:
        return jsonify({
            'status': 'failure',
            'message': 'caseId is required'
        }), 400
    
    caseCreationdb = mongo_conn.case
    
    caseId_present = caseCreationdb.find_one({'_id': ObjectId(caseId), 'caseDeletion': False})
        
    if not caseId_present:
        return jsonify({
            'status': 'failure',
            'message': 'caseId not present in the database, Please create the case'
        }), 400
    else:
        logger.info(f"Entered into the video_upload function---> caseId - {caseId}, videoFiles - {videoFiles}, facialAnalysis - {facialAnalysis}, numberPlateAnalysis - {numberPlateAnalysis}")
        
        if videoFiles != "" and facialAnalysis != "" and numberPlateAnalysis != "":
            foldername = caseId
            startTime = time.time()
            logger.info(f"count files :{len(videoFiles)}")
            fileListUpdate = []
            try:
                for file in videoFiles:
                    originalname = file.filename
                    logger.info(f"file :{file.filename}")
                    filepath = f'{os.getcwd()}/parse_files/{foldername}'
                    if not os.path.exists(filepath):
                        os.makedirs(filepath)
                    file.save(f"{filepath}/{originalname}")
                    filePath = f"{filepath}/{originalname}"
                    fileHashId = calculate_file_hash(filePath, hash_algorithm='sha256')
                    mongoaValue = mongo_conn.filemanager.insert_one({'startTime': startTime, 
                                                                    'caseId':caseId,
                                                                    'filePath':filePath,
                                                                    'filename': originalname, 
                                                                    'fileHashId': fileHashId, 
                                                                    'facialAnalysis': facialAnalysis, 
                                                                    'numberPlateAnalysis': numberPlateAnalysis,  
                                                                    'uploadStatus': 'uploaded successfully', 
                                                                    'facialAnalysisIngestionStatus': 'yet to start', 
                                                                    'numberPlateAnalysisIngestionStatus': 'yet to start'})
                        
                    videoId = str(mongoaValue.inserted_id)
                    print("videoId:)",videoId)
                    # Retrieve the inserted document to get the updated case_status
                    inserted_document = mongo_conn.filemanager.find_one({'_id': mongoaValue.inserted_id})

                    # Extract the case_status from the inserted document
                    uploadStatus = inserted_document.get('uploadStatus', 'Status not found')  
                    
                    fileListUpdate.append({"file_name":filePath, "videoId":videoId}) 
                    
                return jsonify({
                    'status':"success",
                    'message': uploadStatus,
                    'data':{
                        'caseId':caseId,
                        'fileData':fileListUpdate
                    }
                }), 200
            except Exception as e:
                return jsonify({
                    'status': "error",
                    'message': f"Error is, {e}",
                    'data':{
                        'caseId':caseId
                    }
                }), 200
        else:
                return jsonify({
                    'status': "failure",
                    'message': "Mandatory fields is missing",
                    'data':{
                        'caseId':caseId
                    }
                }), 200
          
@app.route('/case_creation', methods=['POST'])
def case_creation():
    data = request.get_json()
    caseNumber = data.get('caseNumber')
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')
    priority = data.get('priority')
    filedBy = data.get('filedBy')
    assignedTo = data.get('assignedTo')
    tags = data.get('tags')
    crimeType = data.get('crimeType')
    location = data.get('location')
    victims = data.get('victims')
    suspects = data.get('suspects')
    witnesses = data.get('witnesses')
    evidence = data.get('evidence')
    comments = data.get('comments')
    dueDate = data.get('dueDate')
    relatedCases = data.get('relatedCases')
    resolution = data.get('resolution')
    legalActions = data.get('legalActions')
    
    # database
    caseCreationdb = mongo_conn.case
    
    try:
        if caseNumber != "" and title != "" and description != "" and status != "" and priority != "" and filedBy != "" and assignedTo != "" and crimeType != "" and location != "":
            logger.info(f"Entered into the case_creation function---> caseNumber - {caseNumber}, title - {title}, description - {description}, status - {status}, priority - {priority}, filedBy - {filedBy}, assignedTo - {assignedTo}, crimeType - {crimeType}, location - {location}")
            caseHashId = calculate_string_hash(caseNumber, hash_algorithm='sha256')
            data = caseCreationdb.find_one({'caseHashId':caseHashId})
            if data:
                caseId = str(data['_id'])
                return jsonify({
                'status':'failure',
                'message': 'already exist',
                'data':{
                    'caseId':caseId
                }
            }), 400
            currentDate = datetime.now().strftime("%d%M%Y%H%M%S%f%z")
            mongoValue = caseCreationdb.insert_one({'caseNumber':caseNumber,
                                                      'title':title,
                                                      'description': description, 
                                                      'status':status, 
                                                      'priority':priority,
                                                      'filedBy' : filedBy,
                                                      'assignedTo': assignedTo,
                                                      'reportedAt': currentDate,
                                                      'lastUpdatedAt': currentDate,
                                                      'tags':tags,
                                                      'crimeType':crimeType,
                                                      'location': location,
                                                      'victims': victims,
                                                      'suspects': suspects,
                                                      'witnesses': witnesses,
                                                      'evidence': evidence,
                                                      'comments': comments,
                                                      'dueDate': dueDate,
                                                      'relatedCases':relatedCases,
                                                      'resolution':resolution,
                                                      'legalActions': legalActions,
                                                      'caseHashId': caseHashId, 
                                                      'caseDeletion':False,
                                                      'caseStatus':'successfully created'})
            # Get the inserted document ID
            caseId = str(mongoValue.inserted_id)
            
            return jsonify({
                'status':'success',
                'message': 'successfully created',
                'data':{
                    'caseId':caseId
                }
            }), 200
        else:
            return jsonify({
                'status':'failure',
                'message': "Mandatory field is missing",
                'data':{
                    'caseNumber':caseNumber
                }
            }), 400
    except Exception as e:
        print(f"error while ingestion, {str(e)}")  
        
@app.route('/case_deletion', methods=['POST'])
def case_deletion():
    data = request.get_json()
    caseId = data.get('caseId')
    # Database collection
    caseCreationdb = mongo_conn.case
    if not caseId:
        return jsonify({
            'status':'failure',
            'message': 'caseId is required'}), 400
    # Find the case by _id
    data = caseCreationdb.find_one({'_id':ObjectId(caseId), 'caseDeletion': False})
    if data:
        # If you want to delete the case
        # result = caseCreationdb.delete_one({'_id':ObjectId(case_id)})
        # if result.deleted_count > 0:
        #     return jsonify({
        #         'message': 'Case successfully deleted'
        #     }), 200
        result = caseCreationdb.update_one(
            {'_id':ObjectId(caseId)},
            {'$set': {'caseDeletion': True}})
        if result:
            return jsonify({
                'status':'success',
                'message': "Case successfully deleted",
                'data':{
                    'caseId':caseId
                }
        }), 200
    else:
        return jsonify({
            'status':'failure',
            'message': 'Case not found',
            'data':{
                    'caseId':caseId
                           }}), 404

@app.route('/case_details', methods=['POST'])
def case_details():
    data = request.get_json()
    caseId = data.get('caseId')
    
    # Database collection
    caseCreationdb = mongo_conn.case
    if not caseId:
        return jsonify({
            'status':'failure',
            'message': 'caseId is required'}), 400
    # Find the case by _id
    data = caseCreationdb.find_one({'_id':ObjectId(caseId),'caseDeletion': False})
    if data:
        data['caseId'] = str(data['_id'])
        del data['_id'] 
        return jsonify({
                        'status':'success',
                        'message':'Retrieved Successfully',
                        'data': {
                            'case_details': json.loads(json_util.dumps(data)) }})
    else:
        return jsonify({
            'status':'failure',
            'message': 'Case not found',
            'data':{
                    'caseId':caseId
                           }
                         }), 404
        
@app.route('/get_all_cases', methods=['GET'])
def get_all_cases():
    caseCreationdb = mongo_conn.case
    allCases = []
    try:
        query = {'caseDeletion': False}
        cursor = caseCreationdb.find(query)
        
        # Convert the cursor to a list and process each document
        for doc in cursor:
            doc['caseId'] = str(doc['_id'])
            del doc['_id'] 
            allCases.append(doc)

        return jsonify({
                'status':'success',
                'message': 'Retrieved Successfully',
                'data': {
                        'all_case_details': allCases }
            }), 200

    except Exception as e:
        logger.error(f"Error retrieving cases: {e}")
        return jsonify({
            'status':'error',
            'message': 'Error retrieving cases'}), 500
        
  
@app.route('/case_update', methods=['POST'])
def case_update(): 
    data = request.get_json()
    caseId = data.get('caseId')
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')
    priority = data.get('priority')
    filedBy = data.get('filedBy')
    assignedTo = data.get('assignedTo')
    tags = data.get('tags')
    crimeType = data.get('crimeType')
    location = data.get('location')
    victims = data.get('victims')
    suspects = data.get('suspects')
    witnesses = data.get('witnesses')
    evidence = data.get('evidence')
    comments = data.get('comments')
    dueDate = data.get('dueDate')
    relatedCases = data.get('relatedCases')
    resolution = data.get('resolution')
    legalActions = data.get('legalActions')
    
    logger.info(f"Enter into the function ============{caseId}")
    
    caseCreationdb = mongo_conn.case
    
    if not caseId:
        return jsonify({
            'status': 'failure',
            'message': 'caseId is required'
        }), 400
    
    try:
        caseId_present = caseCreationdb.find_one({'_id': ObjectId(caseId), 'caseDeletion': False})
        if not caseId_present:
            return jsonify({
                'status': 'failure',
                'message': 'caseId not present in the database, Please create the case'
            }), 400
    except Exception as e:
        logger.info(f"Error Occured in -> {e}")
        return jsonify({
            'status': 'failure',
            'message': f'{caseId} is not a valid ObjectId, it must be a 12-byte input or a 24-character hex string'
        }), 400
    
    def update_field(field_name, field_value):
        if field_value is not None:
            data = caseCreationdb.find_one({"_id": ObjectId(caseId), field_name: field_value, 'caseDeletion': False})
            if not data:
                query = {"_id": ObjectId(caseId), 'caseDeletion': False}
                update = {"$set": {field_name: field_value}}
                caseCreationdb.update_one(query, update, upsert=True)
    
    def update_list_field(field_name, new_items):
        if new_items:
            caseId_present = caseCreationdb.find_one({'_id':ObjectId(caseId), 'caseDeletion': False})
            existing_data = caseId_present.get(field_name, [])
            for items in new_items:
                if items not in existing_data:
                    existing_data.append(items)
            query = {"_id": ObjectId(caseId), 'caseDeletion': False}
            caseCreationdb.update_one(
                query,
                {"$set": {field_name: existing_data}}
            )
    def update_array_field(field_name, new_items):
        if new_items:
            caseId_present = caseCreationdb.find_one({'_id':ObjectId(caseId), 'caseDeletion': False})
            existing_data = caseId_present.get(field_name, [])
            if field_name == "victims" or field_name == "suspects" or field_name == "witnesses":
                for items in new_items:
                    if not any(new_items["name"] == items["name"] and new_items["contactInfo"] == items["contactInfo"] for new_items in existing_data):
                        existing_data.append(items)    
            if field_name == "evidence":
                for items in new_items:
                    if not any(new_items["type"] == items["type"] and new_items["url"] == items["url"] for new_items in existing_data):
                        existing_data.append(items)     
            if field_name == "comments":
                for items in new_items:
                    if not any(new_items["commenter"] == items["commenter"] and new_items["comment"] == items["comment"] and new_items["date"] == items["date"] for new_items in existing_data):
                        existing_data.append(items) 
            if field_name == "legalActions":
                for items in new_items:
                    if not any(new_items["action"] == items["action"] and new_items["status"] == items["status"] for new_items in existing_data):
                        existing_data.append(items) 
            query = {"_id": ObjectId(caseId), 'caseDeletion': False}
            caseCreationdb.update_one(
                query,
                {"$set": {field_name: existing_data}}
            ) 
    if title is not None or description is not None or status is not None or priority is not None or filedBy is not None or assignedTo is not None or tags is not None or crimeType is not None or location is not None or victims is not None or suspects is not None or witnesses is not None or evidence is not None or comments is not None or dueDate is not None or relatedCases is not None or resolution is not None or legalActions is not None:
        update_field('title', title)
        update_field('description', description)
        update_field('status', status)
        update_field('priority', priority)
        update_field('filedBy', filedBy)
        update_field('assignedTo', assignedTo)
        update_list_field('tags', tags)
        update_field('crimeType', crimeType)
        update_field('location', location)
        update_array_field('victims', victims)
        update_array_field('suspects', suspects)
        update_array_field('witnesses', witnesses)
        update_array_field('evidence', evidence)
        update_array_field('comments', comments)
        update_field('dueDate', dueDate)
        update_list_field('relatedCases', relatedCases)
        update_field('resolution', resolution)
        update_array_field('legalActions', legalActions)
        return jsonify({
        'status': 'success',
        'message': 'Case updated successfully'
    }), 200
        
    else:
         return jsonify({
        'status': 'failure',
        'message': 'Give a field to update it'
    }), 400
         
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
