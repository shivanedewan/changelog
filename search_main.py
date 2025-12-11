


from fastapi import FastAPI, Query, HTTPException,Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse,HTMLResponse,FileResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Optional, AsyncGenerator,Dict, Any,Tuple
from starlette.responses import StreamingResponse
import httpx
import logging
import mimetypes
import os
from dotenv import load_dotenv
import json 
from datetime import datetime,timezone,time,timedelta
import re
from urllib.parse import unquote
import mammoth
from pathlib import Path
import urllib.parse


# these are new things
import sqlite3
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import Depends, status, BackgroundTasks
from passlib.context import CryptContext
from jose import JWTError, jwt


app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")



# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # change this when you run on production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],)



# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/app.log"),         # Write to logs/app.log
        logging.StreamHandler()                      # Also print to console
    ]
)

logger = logging.getLogger(__name__)








# Elasticsearch configuration
ES_HOST = "http://localhost:9200/"
LOG_INDEX = "logging"


idx_url="http://localhost:9200/my_index"

# --- Auth Configuration ---
SECRET_KEY = "your-secret-key-keep-it-secret" # In production, use env var
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 43200 # 30 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# --- SQLite User DB ---
DB_NAME = "users.db"

def init_db():
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                hashed_password TEXT
            )
        ''')
        # Create test user if not exists
        cursor.execute("SELECT * FROM users WHERE username = 'testusername'")
        if not cursor.fetchone():
            hashed = pwd_context.hash("testpassword")
            cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", ("testusername", hashed))
        conn.commit()

init_db()

# --- Auth Models & Utils ---
class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    query_token: Optional[str] = Query(None, alias="token")
):
    final_token = token or query_token
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if not final_token:
        raise credentials_exception

    try:
        payload = jwt.decode(final_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    except JWTError:
        raise credentials_exception
    return User(username=username)

# --- History Endpoint ---
@app.get("/history")
async def get_user_history(
    user: User = Depends(get_current_user),
    from_param: int = Query(0, alias="from"),
    size: int = 20,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
):
    """
    Fetch user history (searches, views, downloads).
    Defaults to last 30 days if no dates provided.
    """
    
    must_conditions = [{"term": {"username.keyword": user.username}}]
    
    range_query = {}
    if start_date:
        range_query["gte"] = start_date
    else:
        # Default to 30 days ago if no start date
        thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        range_query["gte"] = thirty_days_ago
        
    if end_date:
        # Add time to end date to include the whole day
        range_query["lte"] = end_date
        
    must_conditions.append({"range": {"timestamp": range_query}})
    
    query = {
        "query": {
            "bool": {
                "must": must_conditions
            }
        },
        "sort": [{"timestamp": "desc"}],
        "from": from_param,
        "size": size
    }
    
    try:
        async with httpx.AsyncClient() as client:
            url = f"{ES_HOST}{LOG_INDEX}/_search"
            response = await client.post(url, json=query)
            
            if response.status_code == 404:
                return {"history": []}
                
            if response.status_code != 200:
                logger.error(f"Error fetching history: {response.text}")
                return {"history": []}
                
            data = response.json()
            hits = data.get("hits", {}).get("hits", [])
            history = [hit["_source"] for hit in hits]
            return {"history": history}
            
    except Exception as e:
        logger.error(f"History fetch failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch history")

# --- Change Password Endpoint ---
class PasswordChange(BaseModel):
    old_password: str
    new_password: str

@app.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    user: User = Depends(get_current_user)
):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (user.username,))
        row = cursor.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
            
        current_hashed_password = row[0]
        
        if not verify_password(password_data.old_password, current_hashed_password):
            raise HTTPException(status_code=400, detail="Incorrect old password")
            
        new_hashed_password = pwd_context.hash(password_data.new_password)
        cursor.execute("UPDATE users SET hashed_password = ? WHERE username = ?", (new_hashed_password, user.username))
        conn.commit()
        
    return {"message": "Password updated successfully"}

# --- Async Logging ---
async def log_user_action(username: str, action: str, details: Dict[str, Any]):
    log_entry = {
        "username": username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details
    }
    try:
        async with httpx.AsyncClient() as client:
             url = f"{ES_HOST}{LOG_INDEX}/_doc"
             await client.post(url, json=log_entry)
    except Exception as e:
        logger.error(f"Failed to log action: {e}")

# --- Login Endpoint ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM users WHERE username = ?", (form_data.username,))
        row = cursor.fetchone()
    
    if not row or not verify_password(form_data.password, row[0]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": form_data.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

def to_epoch_millis(date_str):
    dt_naive=datetime.strptime(date_str,"%Y-%m-%d")
    dt_aware_utc=datetime.combine(dt_naive.date(),time.min,tzinfo=timezone.utc)
    return int(dt_aware_utc.timestamp())




@app.post("/handle-attachment-link")
async def handle_attachment_link(
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any] = Body(...),
    user: User = Depends(get_current_user)
):
    print("hello")
    ProphecyId = payload.get("app_id")
    ParentProphecyId = payload.get("parent_app_id")
    is_attachment = payload.get("is_attachment")


    # check once with sir
    MAX_ATTACHMENT_RESULTS=1000
    
    print(f"{ProphecyId}, {ParentProphecyId}re, {is_attachment}")
    if is_attachment=="False":
        is_attachment=0

    if ProphecyId is None and ParentProphecyId is None:
        raise HTTPException(status_code=400, detail="Required fields missing: app_id, parent_app_id, is_attachment")

    if is_attachment:
        print(f"{ParentProphecyId} hello")
        # If it is an attachment, find parent where AppId == ParentAppId
        

        query={ "query": {
            "bool": {
              "must": [
                {
                  "term": {
                    "ProphecyId.keyword": ParentProphecyId
                  }
                }
              ],
              "must_not": [],
              "should": []
            }
          },
          "highlight":{
          "fields":{
           "Text": {}
          }
          },
          "sort": [
            {"DocumentDate": "desc"},
            {"ProphecyId.keyword": "asc"}
              ],
          "size": 1  }

        
    else:
        # If it is a main doc, find all attachments where ParentAppId == AppId
        print(ProphecyId)
        query={ "query": {
            "bool": {
              "must": [
                {
                  "term": {
                    "ParentProphecyId.keyword": ProphecyId
                  }
                }
              ],
              "must_not": [],
              "should": []
            }
          },
          "highlight":{
          "fields":{
           "Text": {}
          }
          },
          "size": MAX_ATTACHMENT_RESULTS,
          "sort": [
            {"DocumentDate": "desc"},
            {"ProphecyId.keyword": "asc"}
                     ]  }

        

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            url = f"{idx_url}/_search"
            response = await client.post(url, json=query)

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500,
                    detail=f"Elasticsearch error: {response.status_code} - {response.text}"
                )

        data = response.json()
        raw_hits = data.get("hits", {}).get("hits", [])
        print(len(raw_hits))

        # Process highlights
        processed_hits = []
        for hit in raw_hits:
            source = hit["_source"]
            highlight = hit.get("highlight", {}).get("Text", [])
            if highlight:
                source["highlighted_text"] = highlight[0]
            else:
                source["highlighted_text"] = source.get("Text", "")
            
            processed_hit = {
                **hit,
                "_source": source
            }
            processed_hits.append(processed_hit)

        documents = [hit["_source"] for hit in processed_hits]
        print(len(documents))
        
        # handle the case where there might be 100 attactcments
        
        # Log the action
        background_tasks.add_task(
            log_user_action, 
            user.username, 
            "view_attachment_context", 
            {"app_id": ProphecyId, "parent_app_id": ParentProphecyId, "is_attachment": is_attachment}
        )

        return JSONResponse(content={
            "documents": documents,
            "next_search_after": None
        })
    except httpx.RequestError as e:
        logger.error(f"Elasticsearch connection error: {str(e)}")
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")
    except Exception as e:
        logger.exception("Unexpected server error")
        raise HTTPException(status_code=500, detail="Internal Server Error")






    

# ---------------------------------------
# ---------------------------------------
async def search_elasticsearch(
    queries: List[str],
    size: int,
    search_type: str = "any",
    search_after: Optional[List] = None,
    filters: Optional[Dict[str, List[str]]] = None,
    date_range: Optional[Dict[str, str]] = None,
    parents_only: bool =False,
    enable_fuzzy: bool= False,
    from_offset: Optional[int] = None,
    include_attachments: bool = False
) -> Tuple[List[dict], Optional[List]]:

    must_clauses = []
    should_clauses = []
    print(queries)
    print(parents_only)
    search_fields_keywords=["OriginalName.keyword","ProphecyId.keyword","ParentProphecyId.keyword"]

    # --- search_type logic unchanged ---
    if search_type == "all":
        for q in queries:
            sub_clauses=[]
            if enable_fuzzy:
                sub_clauses.append({
                    "match_phrase": {"Text": {"query": q, "boost": 4}}
                })
                sub_clauses.append({
                    "match": {
                        "Text": {"query": q, "operator": "and", "fuzziness": "AUTO",
                                 "prefix_length": 2, "max_expansions": 50, "boost": 2}
                    }
                })
            else:
                sub_clauses.append({
                    "match_phrase": {"Text": {"query": q, "boost": 3}}
                })
            for field in search_fields_keywords:
                sub_clauses.append({
                    "term": {field: {"value": q, "boost": 5}}
                })
            must_clauses.append({"bool": {"should": sub_clauses, "minimum_should_match": 1}})
    elif search_type == "any":
        for q in queries:
            sub_clauses=[]
            if enable_fuzzy:
                sub_clauses.append({
                    "match_phrase": {"Text": {"query": q, "boost": 4}}
                })
                sub_clauses.append({
                    "match": {
                        "Text": {"query": q, "operator": "and", "fuzziness": "AUTO",
                                 "prefix_length": 2, "max_expansions": 50, "boost": 2}
                    }
                })
            else:
                sub_clauses.append({
                    "match_phrase": {"Text": {"query": q, "boost": 3}}
                })
            for field in search_fields_keywords:
                sub_clauses.append({
                    "term": {field: {"value": q, "boost": 5}}
                })
            should_clauses.append({"bool": {"should": sub_clauses, "minimum_should_match": 1}})
    else:
        if queries:
            raise HTTPException(status_code=400, detail="Invalid search_type. Use 'any' or 'all'.")


    # ---------- FILTERS ----------
    if filters:
        for field, values in filters.items():
            if values:
                keyword_field = f"{field}.keyword" if not field.endswith(".keyword") else field
                must_clauses.append({"terms": {keyword_field: values}})

    # ---------- DATE RANGE ----------
    if date_range:
        range_filter = {}
        if date_range.get("from"):
            range_filter["gte"] = to_epoch_millis(date_range["from"])
        if date_range.get("to"):
            to_dt_naive=datetime.strptime(date_range["to"],"%Y-%m-%d")
            next_day = to_dt_naive.date() + timedelta(days=1)
            next_start = datetime.combine(next_day, time.min, tzinfo=timezone.utc)
            range_filter["lt"] = int(next_start.timestamp())
        if range_filter:
            must_clauses.append({"range": {"DocumentDate": range_filter}})

    if parents_only:
        must_clauses.append({"term": {"IsAttachment.keyword": "False"}})

    # ---------- SEARCH QUERY ----------
    query_body = {
        "bool": {
            "must": must_clauses,
            "should": should_clauses,
            "minimum_should_match": 1 if should_clauses else 0
        }
    }

    # ---------- BASE SEARCH BODY ----------
    search_body = {
        "size": size,
        "sort": [
            {"DocumentDate": "desc"},
            {"ProphecyId.keyword": "asc"}
        ],
        "track_total_hits": True,
        "query": query_body,
        "highlight": {
            "type":"unified",
            "fields": {
                "Text": {"fragment_size":200,
                         "number_of_fragments":3,
                         "boundary_scanner":"sentence"}
            },
            "pre_tags": ["<mark>"],
            "post_tags": ["</mark>"]
        }
    }

    if from_offset is not None and from_offset>=0:
        search_body["from"]=from_offset
    elif search_after:
        search_body["search_after"] = search_after

    # -----------------------------------------------------------
    # ⭐ FIX ADDED: GLOBAL AGGREGATION (IGNORES SEARCH QUERY)
    # -----------------------------------------------------------
    search_body["aggs"] = {

        "doctype_counts": {
            "terms": {"field": "DocType.keyword", "size": 100}
        },
        "branchtype_counts": {
            "terms": {"field": "Branch.keyword", "size": 100}
        },
        "extensiontype_counts": {
            "terms": {"field": "FileExtension.keyword", "size": 100}
        },

        # ⭐ FIX ADDED — global block so attachment counts ignore filtering
        "all_attachments": {
            "global": {},               # ← KEY FIX
            "aggs": {
                "attachment_counts": {
                    "terms": {
                        "field": "ParentProphecyId.keyword",
                        "size": 300
                    },
                    "aggs": {
                        "top_attachments": {
                            "top_hits": {
                                "size": 100,
                                "_source": [
                                    "ProphecyId",
                                    "FileName",
                                    "FileExtension",
                                    "SystemPath",
                                    "IsAttachment"
                                ]
                            }
                        }
                    } if include_attachments else {}
                }
            }
        }
    }
    # -----------------------------------------------------------


    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            print("before sending to es")
            url = f"{idx_url}/_search"
            response = await client.post(url, json=search_body)

            highlight_disabled=False  
            if response.status_code == 400:
                highlight_disabled=True
                search_body.pop("highlight",None)
                response = await client.post(url, json=search_body)

            if response.status_code != 200:
                raise HTTPException(
                    status_code=500,
                    detail=f"ES error {response.status_code}: {response.text}"
                )

        data = response.json()
        raw_hits = data.get("hits", {}).get("hits", [])

        # -----------------------------------------------------------
        # ⭐ FIX UPDATED: READ ATTACHMENTS FROM GLOBAL AGG
        # -----------------------------------------------------------
        attachment_buckets = (
            data["aggregations"]
            ["all_attachments"]
            ["attachment_counts"]
            ["buckets"]
        )

        attachment_map = {b["key"]: b["doc_count"] for b in attachment_buckets}

        attachment_list_map = {}
        if include_attachments:
            for b in attachment_buckets:
                parent_id = b["key"]
                hits = b.get("top_attachments", {}).get("hits", {}).get("hits", [])
                
                # Process attachments to ensure FileName is populated
                processed_attachments = []
                for h in hits:
                    att_source = h["_source"]
                    if "SystemPath" in att_source and att_source["SystemPath"]:
                        att_source["FileName"] = os.path.basename(att_source["SystemPath"])
                    processed_attachments.append(att_source)
                    
                attachment_list_map[parent_id] = processed_attachments
        # -----------------------------------------------------------


        total_hits = data.get("hits",{}).get("total",{}).get("value",0)

        # ---------- PROCESS HITS ----------
        processed_hits = []
        for hit in raw_hits:
            source = hit.get("_source",{})
            text_full = source.get("Text") or ""
            highlight_list = (hit.get("highlight") or {}).get("Text", [])
            source["Text"]=text_full[:100]

            if highlight_list:
                # join them nicely with line breaks
                source["highlighted_text"] = "<br>".join(highlight_list)
            else:
                source["highlighted_text"] = source["Text"]

            # attachment count injection
            if source.get("IsAttachment") == "False":
                prophecy_id = source.get("ProphecyId","")
                a_count = attachment_map.get(prophecy_id, 0)
                if include_attachments:
                    source["AttachmentList"] = attachment_list_map.get(prophecy_id, [])
            else:
                a_count = 0

            source["a_count"]=a_count
            
            # Ensure FileName is populated from SystemPath if available
            if "SystemPath" in source and source["SystemPath"]:
                source["FileName"] = os.path.basename(source["SystemPath"])

            processed_hits.append({
                **hit,
                "_source": source
            })

        last_sort_value = raw_hits[-1]["sort"] if raw_hits else None

        # Simple agg extraction
        doc_type_counts={}
        branch_type_counts={}
        extension_type_counts={}

        if "aggregations" in data:
            for bucket in data["aggregations"]["doctype_counts"].get("buckets",[]):
                doc_type_counts[bucket["key"]] = bucket["doc_count"]

            for bucket in data["aggregations"]["branchtype_counts"].get("buckets",[]):
                branch_type_counts[bucket["key"]] = bucket["doc_count"]

            for bucket in data["aggregations"]["extensiontype_counts"].get("buckets",[]):
                extension_type_counts[bucket["key"]] = bucket["doc_count"]

        return processed_hits, last_sort_value, doc_type_counts, branch_type_counts, extension_type_counts, total_hits

    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail="Elasticsearch is unavailable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------
@app.post("/search")
async def stream_or_paginate_search(
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any] = Body(...),
    user: User = Depends(get_current_user)
):
    """
    Handles search requests: 
    - Streams full results if stream=True 
    - Else paginated fetch (one batch at a time)
    """
    queries = payload.get("queries", [])
    size = payload.get("size", 100)
    search_type = payload.get("search_type", "any")
    filters = payload.get("filters", {})
    date_range = payload.get("date_range", {})
    search_after = payload.get("search_after")  # Optional
    stream = payload.get("stream", False)       # Optional, default False
    parents_only = bool(payload.get("parents_only",False))
    enable_fuzzy = payload.get("enable_fuzzy", False) 

    from_offset = payload.get("from")  # ** new**

    



    # *** NEW ***: Add a validation check to prevent completely empty searches.
    # An empty search (no queries, no filters, no date range) would be a very
    # expensive "match_all" query. Instead of erroring, we return a valid but
    # empty response, which is cleaner for the frontend.
    if not queries and not filters and not date_range:
        return JSONResponse(content={
            "documents": [],
            "next_search_after": None,
            "aggregations": {
                "doctype_counts": {},
                "branchtype_counts": {},
                "extensiontype_counts": {}
            },
            "total": 0
        })
    
    
    if not isinstance(size, int) or size <= 0:
        size = 100  # Fallback safe default

    if stream:
        # Full streaming mode
        async def document_generator() -> AsyncGenerator[str, None]:
            nonlocal search_after
            first = True
            yield "["
            while True:
                hits, search_after = await search_elasticsearch(
                    queries, size, search_type, search_after, filters, date_range, parents_only
                )
                if not hits:
                    break
                for hit in hits:
                    doc_json = hit["_source"]
                    doc_str = f"{'' if first else ','}{json.dumps(doc_json)}"
                    yield doc_str
                    first = False
                if search_after is None:
                    break
            yield "]"

        return StreamingResponse(document_generator(), media_type="application/json")

    else:
        # Paginated mode
        print("abcd")
        hits, last_sort_value,doctype_counts,branchtype_counts,extensiontype_counts,hits_total = await search_elasticsearch(
            queries, size, search_type, search_after, filters, date_range, parents_only, enable_fuzzy, from_offset
        )

        documents = [hit["_source"] for hit in hits]
        
        print("total count")
        print(hits_total)

        
        # Log the search
        background_tasks.add_task(
            log_user_action, 
            user.username, 
            "search", 
            {"queries": queries, "filters": filters, "total_hits": hits_total}
        )
        
        return JSONResponse(content={
            "documents": documents,
            "next_search_after": last_sort_value,
            "aggregations":{
                "doctype_counts": doctype_counts,
                "branchtype_counts": branchtype_counts,
                "extensiontype_counts":extensiontype_counts
            },
            "total":hits_total

        })




@app.get("/api/documents/{system_path:path}", response_class=HTMLResponse)
def get_document_html(
    system_path: str,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user)
):
    """
    Returns HTML content of the document so frontend modal can render it
    Call from frontend:
    /api/documents/${encodeURIComponent(doc.SystemPath)}
    """

    # Decode URL-encoded path
    decoded_path = urllib.parse.unquote(system_path)
    file_path = Path(decoded_path)

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Document not found")

    # ---- 2. If last 3 chars are 'pdf', return file directly ----
    if file_path.suffix.lower() == ".pdf":
        mime_type, _ = mimetypes.guess_type(str(file_path))
        return FileResponse(
            path=file_path,
            media_type=mime_type or "application/pdf",
            filename=file_path.name,
            content_disposition_type="inline"  # open inside browser
        )
    


    # for doc docx
    relative_path = unquote(system_path)

    # Resolve relative path to absolute path based on script directory
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(BASE_DIR, relative_path)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Document not found: {file_path}")


 

    try:
        with open(file_path, "rb") as docx_file:
            result = mammoth.convert_to_html(docx_file)
            html = result.value
        
        # Log the view/download
        background_tasks.add_task(
            log_user_action, 
            user.username, 
            "view_document", 
            {"system_path": system_path}
        )

        return HTMLResponse(content=html)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------
# ★ NEW ENDPOINT: Search with Attachments
# ---------------------------------------
@app.post("/search_with_attachment")
async def search_with_attachment(
    background_tasks: BackgroundTasks,
    payload: Dict[str, Any] = Body(...),
    user: User = Depends(get_current_user)
):
    """
    Same as /search but includes 'AttachmentList' in the document source.
    """
    queries = payload.get("queries", [])
    size = payload.get("size", 100)
    search_type = payload.get("search_type", "any")
    filters = payload.get("filters", {})
    date_range = payload.get("date_range", {})
    search_after = payload.get("search_after")
    parents_only = bool(payload.get("parents_only", False))
    enable_fuzzy = payload.get("enable_fuzzy", False)
    from_offset = payload.get("from")

    # Validation for empty search
    if not queries and not filters and not date_range:
        return JSONResponse(content={
            "documents": [],
            "next_search_after": None,
            "aggregations": {
                "doctype_counts": {},
                "branchtype_counts": {},
                "extensiontype_counts": {}
            },
            "total": 0
        })

    if not isinstance(size, int) or size <= 0:
        size = 100

    # Call search_elasticsearch with include_attachments=True
    hits, last_sort_value, doctype_counts, branchtype_counts, extensiontype_counts, hits_total = await search_elasticsearch(
        queries, size, search_type, search_after, filters, date_range, parents_only, enable_fuzzy, from_offset,
        include_attachments=True # <--- ENABLE ATTACHMENTS
    )

    documents = [hit["_source"] for hit in hits]



    # Log the search
    background_tasks.add_task(
        log_user_action, 
        user.username, 
        "search_with_attachment", 
        {"queries": queries, "filters": filters, "total_hits": hits_total}
    )

    return JSONResponse(content={
        "documents": documents,
        "next_search_after": last_sort_value,
        "aggregations": {
            "doctype_counts": doctype_counts,
            "branchtype_counts": branchtype_counts,
            "extensiontype_counts": extensiontype_counts
        },
        "total": hits_total
    })


# ---------------------------------------
# ★ NEW ENDPOINTS: Prophecy Tool
# ---------------------------------------

@app.get("/api/prophecy/{prophecy_id}")
async def get_prophecy_by_id(
    prophecy_id: str
):
    query = {
        "query": {
            "term": {
                "ProphecyId.keyword": prophecy_id
            }
        },
        "size": 1
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            url = f"{idx_url}/_search"
            response = await client.post(url, json=query)

            if response.status_code != 200:
                 raise HTTPException(status_code=500, detail=f"ES error: {response.text}")

            data = response.json()
            hits = data.get("hits", {}).get("hits", [])

            if not hits:
                return JSONResponse(content={"found": False}, status_code=404)

            hit = hits[0]
            source = hit["_source"]
            
            return {
                "found": True,
                "prophecy_id": source.get("ProphecyId"),
                "system_path": source.get("SystemPath"),
                "access_branches": source.get("access_branches", ""), # Make sure this matches ES field
                "es_id": hit["_id"],
                "index": hit["_index"],
                "source": source # return full source for debugging/display
            }

    except httpx.RequestError as e:
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")


class AccessBranchesUpdate(BaseModel):
    prophecy_id: str
    access_branches: str

@app.post("/api/update-access-branches")
async def update_access_branches(
    update_data: AccessBranchesUpdate
):
    # 1. First find the document to get its ID (if not provided, but we use strict query for safety)
    # Actually we can use update_by_query or find then update. 
    # Let's find first to be safe and get the _id.
    
    # ... Or better, since we know ProphecyId is the key we want to match:

    search_query = {
        "query": {
            "term": {
                "ProphecyId.keyword": update_data.prophecy_id
            }
        }
    }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # A. Search
            url = f"{idx_url}/_search"
            resp = await client.post(url, json=search_query)
            if resp.status_code != 200:
                 raise HTTPException(status_code=500, detail="ES Search failed")
            
            data = resp.json()
            hits = data.get("hits", {}).get("hits", [])
            
            if not hits:
                raise HTTPException(status_code=404, detail="ProphecyId not found")
            
            doc_id = hits[0]["_id"]
            
            # B. Update using _update API
            update_url = f"{idx_url}/_update/{doc_id}"
            update_body = {
                "doc": {
                    "access_branches": update_data.access_branches
                }
            }
            
            update_resp = await client.post(update_url, json=update_body)
            
            if update_resp.status_code not in [200, 201]:
                raise HTTPException(status_code=500, detail=f"Update failed: {update_resp.text}")
                
            return {"message": "Updated successfully", "new_value": update_data.access_branches}

    except httpx.RequestError:
        raise HTTPException(status_code=503, detail="Elasticsearch unavailable")