import React, { useState, useEffect, useContext } from 'react';
import download from 'downloadjs';
import {BrowserRouter as Router, Link} from 'react-router-dom';
import axios from 'axios';
import { confirm } from "react-confirm-box";
import { UserContext } from "../App";
import { useNavigate, useParams } from 'react-router-dom';

const User = () => {
    const { name } = useParams();
  
    const details = {
        name
    }
  
    return details;
}

const FilesList = () => {

  const [filesList, setFilesList] = useState([]);
  const [errorMsg, setErrorMsg] = useState('');

  const {state, dispatch} = useContext(UserContext);
  dispatch({type:"USER", payload:3});

  const dataset = User();

  useEffect(() => {
    const getFilesList = async () => {
      try {
        const { data } = await axios.get(`http://localhost:8070/studentsubmission/get/${dataset.name}`);
        setErrorMsg('');
        setFilesList(data);
      } catch (error) {
        error.response && setErrorMsg(error.response.data);
      }
    };

    getFilesList();
  }, []);

  const downloadFile = async (id, path, mimetype) => {
    try {
      const result = await axios.get(`http://localhost:8070/studentsubmission/download/${id}`, {
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
    <div className="container my-5">
      <br/><br/>
      {errorMsg && <p className="errorMsg">{errorMsg}</p>}
      <table className="table table-hover" style={{ color: 'white'}}>
        <thead>
          <tr>
            <th>Group</th>
            <th>Assignment ID</th>
            <th>Assignment Name</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {filesList.length > 0 ? (
            filesList.map(
              ({ _id, grupid, assignmentid, assignmentname, file_path, file_mimetype }) => (
                <tr key={_id}>
                  <td className="file-title">{grupid}</td>
                  <td className="file-description">{assignmentid}</td>
                  <td className="file-description">{assignmentname}</td>
                  <td align='right'>
                    <button type="button" class="btn btn-warning" style={{opacity: "70%"}} onClick={() => downloadFile(_id, file_path, file_mimetype)}>
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-download" viewBox="0 0 16 16">
                      <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                      <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
                    </svg>
                    </button>
                  </td>
                </tr>
              )
            )
          ) : (
            <tr>
              <td colSpan={3} style={{ fontWeight: '300' }}>
                No files found.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
};

export default FilesList;