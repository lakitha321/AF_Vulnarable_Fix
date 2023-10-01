import React, { useState, useEffect, useContext } from 'react';
import download from 'downloadjs';
import {BrowserRouter as Router, Link} from 'react-router-dom';
import axios from 'axios';
import { confirm } from "react-confirm-box";
import { UserContext } from "../App";
import { useNavigate, useParams } from 'react-router-dom';
import {Modal} from "react-bootstrap";

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

  const [modalShow, setModalShow] = useState(false);

  const [id, setId] = useState('');
  const [status, setStatus] = useState('');

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

  function stratAgain(rid, id){

    axios.put(`http://localhost:8070/studentgroup/updateGroupStaff/${id}`).then((res) => {
    alert(res.data);
    if(res.data === "Group updated"){
        axios.delete(`http://localhost:8070/studentsubmission/deleteSubmission/${rid}`).then(() => {
            alert("Submission deleted");
            window.location.reload(false);
        })
    }
    }).catch((err) => {
        alert(err);
    })
  }

  const passValues = (id, status) => {

    setId(id);
    setStatus(status);

    setModalShow(true);
    }

  function updateSubData(){

    var feedback = document.getElementById("fdbk").value;

    const updateSub = {
        status,
        feedback
    }

    axios.put(`http://localhost:8070/studentsubmission/update/${id}`, updateSub).then((res) => {
        window.location.reload(false);
    }).catch((err) => {
        alert(err);
    })

  }

  function MyVerticallyCenteredModal(props) {
    return (
      <Modal
        {...props}
        size="lg"
        aria-labelledby="contained-modal-title-vcenter"
        centered
        align='center'
      >
        <Modal.Header closeButton>
          <Modal.Title>
            Please provide a feedback!
          </Modal.Title>
        </Modal.Header>
        <Modal.Body>
        <form class="d-flex" onSubmit={() => updateSubData()}>
            <input class="form-control me-2" id="fdbk" type="search" placeholder="Enter a feedback" aria-label="Search" required />
            <button class="btn btn-primary" type="submit">
                Done
            </button>
        </form>
        </Modal.Body>
      </Modal>
    );
  }

  return (
    <div className="container my-5">
        <MyVerticallyCenteredModal
            show={modalShow}
            onHide={() => setModalShow(false)}
        />
      <br/><br/>
      {errorMsg && <p className="errorMsg">{errorMsg}</p>}
      <table className="table table-hover" style={{ color: 'white'}}>
        <thead>
          <tr>
            <th>Group</th>
            <th>Assignment ID</th>
            <th>Assignment Name</th>
            <th>Status</th>
            <th>Feedback</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {filesList.length > 0 ? (
            filesList.map(
              ({ _id, grupid, assignmentid, assignmentname, panel, file_path, file_mimetype, feedback, status }) => (
                <>
                {panel === "YES" ? (
                  <>
                  <tr key={_id}>
                    <td className="file-title">{grupid}</td>
                    <td className="file-description">{assignmentid}</td>
                    <td className="file-description">{assignmentname}</td>

                      {status ? (
                          <>
                          <td className="file-description">{status}</td>
                          </>
                      ):(
                          <>
                          <td className="file-description">empty</td>
                          </>
                      )}

                      {feedback ? (
                          <>
                          <td className="file-description">{feedback}</td>
                          </>
                      ):(
                          <>
                          <td className="file-description">empty</td>
                          </>
                      )}

                      <td align='right'>

                      {status ? (
                          <>
                          </>
                      ):(
                        <>
                          <>
                          <button type="button" class="btn btn-success" style={{opacity: "70%"}} onClick={() => passValues(_id, "Accepted")}>
                              Accept
                          </button>
                          &nbsp;&nbsp;
                          <button type="button" class="btn btn-danger" style={{opacity: "70%"}} onClick={() => passValues(_id, "Rejected")}>
                              Reject
                          </button>
                          </>
                        </>
                      )}
                      {status === "Rejected" ? (
                          <>
                          <button type="button" class="btn btn-danger" style={{opacity: "70%"}} onClick={() => stratAgain(_id, grupid)}>
                              Start again
                          </button>
                          </>
                      ):(
                          <>
                          </>
                      )}
                      &nbsp;&nbsp;
                      <button type="button" class="btn btn-warning" style={{opacity: "70%"}} onClick={() => downloadFile(_id, file_path, file_mimetype)}>
                      <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-download" viewBox="0 0 16 16">
                        <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                        <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
                      </svg>
                      </button>
                    </td>
                  </tr>
                  </>
                ):(
                  <></>
                )}
                
                </>
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