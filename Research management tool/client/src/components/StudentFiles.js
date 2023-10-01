import React, { useState, useEffect, useContext } from 'react';
import download from 'downloadjs';
import {BrowserRouter as Router, Link} from 'react-router-dom';
import axios from 'axios';
import { confirm } from "react-confirm-box";
import { UserContext } from "../App";
import Card from "react-bootstrap/Card";

const StudentFilesList = () => {

  const [filesList, setFilesList] = useState([]);
  const [errorMsg, setErrorMsg] = useState('');

  const {state, dispatch} = useContext(UserContext);
  dispatch({type:"USER", payload:1})

  useEffect(() => {
    const getFilesList = async () => {
      try {
        const { data } = await axios.get("http://localhost:8070/assignment/getAllAssigbments/");
        setErrorMsg('');
        setFilesList(data.dat);
      } catch (error) {
        error.response && setErrorMsg(error.response.data);
      }
    };

    getFilesList();
  }, []);

  const downloadFile = async (id, path, mimetype) => {
    try {
      const result = await axios.get(`http://localhost:8070/assignment/download/${id}`, {
        responseType: 'blob'
      });
      const split = path.split('/');
      const filename = split[split.length - 1];
      setErrorMsg('');
      return download(result.data, filename, mimetype);
    } catch (error) {
      if (error.response && error.response.status === 400) {
        setErrorMsg('Error while downloading file. Try again later');
      }
    }
  };

  return (
    <div className="container">
        <br/><br/><br/><br/>
      {errorMsg && <p className="errorMsg">{errorMsg}</p>}
        <div className="row">
          {filesList.length > 0 ? (
            filesList.map(
              ({ _id, title, description, file_path, file_mimetype }) => (
                <div className="col-4" align="center" key={_id}>
                    <Card style={{ width: '15rem', backgroundColor: 'transparent', borderColor: 'white' }}>
                    <Card.Body>
                        <Card.Title style={{ color: 'white'}}>{title}</Card.Title>
                        <Card.Text style={{ color: 'white'}}>
                        {description}
                        </Card.Text>
                        <button type="button" className="btn btn-primary" style={{width: '13rem'}} onClick={() => downloadFile(_id, file_path, file_mimetype)}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" className="bi bi-download" viewBox="0 0 16 16">
                            <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                            <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
                        </svg>&nbsp;&nbsp;&nbsp;Download file
                        </button>
                    </Card.Body>
                    </Card><br/><br/><br/>
                </div>
              )
            )
          ) : (
            <p>No files found. Please add some.</p>
          )}
        </div>
    </div>
  );
};

export default StudentFilesList;