import React, { useState, useRef, useEffect, useContext } from 'react';
import { Form, Row, Col, Button } from 'react-bootstrap';
import download from 'downloadjs';
import Dropzone from 'react-dropzone';
import axios from 'axios';
import { confirm } from "react-confirm-box";
import { useNavigate, useParams } from 'react-router-dom';
import { UserContext } from "../App";
import Card from "react-bootstrap/Card";

const User = () => {
  const { id, name, grpid, panel } = useParams();

  const details = {
      id,
      name,
      grpid,
      panel
  }

  return details;
}

const StudentSubArea = (props) => {

  const {state1, dispatch} = useContext(UserContext);
  dispatch({type:"USER", payload:1})

  const dataset = User();

  const navigate = useNavigate();

  const [file, setFile] = useState(null); // state for storing actual image
  const [previewSrc, setPreviewSrc] = useState(''); // state for storing previewImage
  const [state, setState] = useState({
    title: '',
    description: ''
  });
  const [errorMsg, setErrorMsg] = useState('');
  const [isPreviewAvailable, setIsPreviewAvailable] = useState(false); // state to show preview only for images
  const dropRef = useRef(); // React ref for managing the hover state of droppable area

  state.title = dataset.name;
  state.description = dataset.grpid;

  const handleInputChange = (event) => {
    setState({
      ...state,
      [event.target.name]: event.target.value
    });
  };
  

  const handleOnSubmit = async (event) => {
    event.preventDefault();

    try {
        const { title, description } = state;
        if (title.trim() !== '' && description.trim() !== '') {
          if (file) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('grupid', description);
            formData.append('assignmentid', dataset.id);
            formData.append('assignmentname', title);
            formData.append('panel', dataset.panel);

            if(description === "Not defined"){
              alert("You must have a group to submit!");
              return;
            }
    
            setErrorMsg('');
            await axios.post("http://localhost:8070/studentsubmission/uploadsubmission/", formData, {
              headers: {
                'Content-Type': 'multipart/form-data'
              }
            }).then((res)=>{
              alert(res.data);
              window.location.reload(false);
              // navigate('/studentsubmissions');
            });
          } else {
            setErrorMsg('Please select a file to add.');
          }
        } else {
          setErrorMsg('Please enter all the field values.');
        }
      } catch (error) {
        //error.response && setErrorMsg(error.response.data);
      }
  };

  const onDrop = (files) => {
    const [uploadedFile] = files;
    setFile(uploadedFile);
  
    const fileReader = new FileReader();
    fileReader.onload = () => {
      setPreviewSrc(fileReader.result);
    };
    fileReader.readAsDataURL(uploadedFile);
    console.log(uploadedFile);
    setIsPreviewAvailable(uploadedFile.name.match(/\.(jpeg|jpg|png)$/));
  };

  const [filesList, setFilesList] = useState([]);
  const [errorms, setError] = useState('');

  useEffect(() => {
    const getFilesList = async () => {
      try {
        const { data } = await axios.get(`http://localhost:8070/studentsubmission/get/${dataset.id}/${dataset.grpid}`);
        setError('');
        setFilesList(data);
      } catch (error) {
        error.response && setError(error.response.data);
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
      setError('');
      return download(result.data, filename, mimetype);
    } catch (error) {
      if (error.response && error.response.status === 400) {
        setError('Error while downloading file. Try again later');
      }
    }
  };

  const deleteFile = async (id) => {
    console.log(id);

    const result1 = await confirm("Are you sure do you want to delete?");
    
    if (result1) {
      const result2 = await confirm("Your submission wil be permenantly deleted!!!");
      if(result2){
        axios.delete(`http://localhost:8070/studentsubmission/deleteSubmission/${id}`).then((res) => {
            alert("Deleted");
            window.location.reload(false);
        }).catch((err) => {
            alert(err);
        });
      }
      
    }
  };

  return (
    <>
      <div className="container"><br/><br/><br/>
      <br/>
      {errorms && <p>{errorms}</p>}
          {filesList.length > 0 ? (
            filesList.map(
              ({ _id, grupid, assignmentname, file_path, file_mimetype, createdAt, status, feedback }) => (
                <div className="col-12" align="center" key={_id}>
                  <br/>
                  <p className="fs-4" style={{ color: 'white'}}>{assignmentname} <green style={{color:"#6FD25A"}}>submitted</green></p><br/>
                  <Card style={{ width: '60rem' }}>
                  <Card.Body>
                    <br/>
                      <Card.Title align="center">{assignmentname}</Card.Title>
                      <Card.Subtitle align="center">Group ID : {grupid}</Card.Subtitle>
                      <br/>
                      <Card.Text align="center">Submitted on {createdAt[0]}{createdAt[1]}{createdAt[2]}{createdAt[3]}{createdAt[4]}{createdAt[5]}{createdAt[6]}{createdAt[7]}{createdAt[8]}{createdAt[9]} at {createdAt[11]}{createdAt[12]}{createdAt[13]}{createdAt[14]}{createdAt[15]}</Card.Text>
                      <br/>
                      <div className="container">
                      <div className="row">
                        <div className="col">
                        <button type="button" className="btn btn-warning" style={{opacity: "90%", width: '20rem'}} onClick={() => downloadFile(_id, file_path, file_mimetype)}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" className="bi bi-download" viewBox="0 0 16 16">
                          <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                          <path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/>
                        </svg>&nbsp;&nbsp;Download
                        </button>
                        </div>
                        <div className="col">
                        <button type="button" className="btn btn-danger" style={{opacity: "90%", width: '20rem'}} onClick={() => deleteFile(_id)}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" className="bi bi-trash3" viewBox="0 0 16 16">
                        <path d="M6.5 1h3a.5.5 0 0 1 .5.5v1H6v-1a.5.5 0 0 1 .5-.5ZM11 2.5v-1A1.5 1.5 0 0 0 9.5 0h-3A1.5 1.5 0 0 0 5 1.5v1H2.506a.58.58 0 0 0-.01 0H1.5a.5.5 0 0 0 0 1h.538l.853 10.66A2 2 0 0 0 4.885 16h6.23a2 2 0 0 0 1.994-1.84l.853-10.66h.538a.5.5 0 0 0 0-1h-.995a.59.59 0 0 0-.01 0H11Zm1.958 1-.846 10.58a1 1 0 0 1-.997.92h-6.23a1 1 0 0 1-.997-.92L3.042 3.5h9.916Zm-7.487 1a.5.5 0 0 1 .528.47l.5 8.5a.5.5 0 0 1-.998.06L5 5.03a.5.5 0 0 1 .47-.53Zm5.058 0a.5.5 0 0 1 .47.53l-.5 8.5a.5.5 0 1 1-.998-.06l.5-8.5a.5.5 0 0 1 .528-.47ZM8 4.5a.5.5 0 0 1 .5.5v8.5a.5.5 0 0 1-1 0V5a.5.5 0 0 1 .5-.5Z"/>
                        </svg>&nbsp;&nbsp;Delete
                        </button>
                        </div>
                      </div>
                      </div>
                      <br/><br/>  
                  </Card.Body>
                  </Card><br/><br/>
                  {status ? (
                    <>
                    <p className="fs-4" style={{ color: 'white'}}>Status : {status}</p>
                    </>
                  ):(
                    <></>
                  )}
                  {feedback ? (
                    <>
                    <p className="fs-4" style={{ color: 'white'}}>Panel Feedback</p>
                    <p className="fs-5" style={{ color: 'white'}}>{feedback}</p>
                    </>
                  ):(
                    <></>
                  )}
                </div>
              )
            )
          ) : (
            <div className="col-12" align="center">
              <br/>
                <p className="fs-4" style={{color:"red"}}>Upload before the deadline!!</p><br/>
            <Card style={{ width: '60rem', backgroundColor:'transparent' }}>
            <Card.Body>
              <br/>
            <Form className="search-form" onSubmit={handleOnSubmit}>
              {errorMsg && <p>{errorMsg}</p>}
              <Row>
                <Col>
                  <Form.Group controlId="title">
                    <Form.Control style={{color:'white', backgroundColor:'transparent', borderColor:'white'}}
                      type="text"
                      name="title"
                      value={state.title || ''}
                      onChange={handleInputChange}
                    />
                  </Form.Group>
                </Col>
              </Row>
              <br/>
              <Row>
                <Col>
                  <Form.Group controlId="description">
                    <Form.Control style={{color:'white', backgroundColor:'transparent', borderColor:'white'}}
                      type="text"
                      name="description"
                      value={state.description || ''}
                      placeholder="Enter group ID"
                      onChange={handleInputChange}
                    />
                  </Form.Group>
                </Col>
              </Row>
              <br/>
              <div className="upload-section">
              <Dropzone onDrop={onDrop}>
                  {({ getRootProps, getInputProps }) => (
                  <div className="p-3 mb-2 bg-dark text-white" {...getRootProps({ className: 'drop-zone' })} ref={dropRef}>
                      <input {...getInputProps()} />
                      <div className='border border-primary'>
                          <br/> <br/>
                      <p style={{color:'white'}}>Drag and drop a file OR click here to select a file</p>
                      <br/>
                          {file && (
                          <div>
                              <strong style={{color:'white'}}>Selected file: &nbsp; {file.name}</strong>
                          </div>
                          )}
                          {previewSrc ? (
                              isPreviewAvailable ? (
                              <div className="w-50 p-3">
                                  <img className='choosedImg' src={previewSrc} alt="Preview" />
                              </div>
                              ) : (
                              <div className="preview-message">
                                  <p style={{color:'white'}}>No preview available for this file</p>
                              </div>
                              )
                          ) : (
                              <div className="preview-message">
                              <p></p>
                              </div>
                          )}
                      </div>
                  </div>
                  )}
              </Dropzone>
              </div>
              <br/>
              <Button className="btn btn-success" type="submit" style={{ width: '20rem' }}>
              <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-upload" viewBox="0 0 16 16">
                <path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/>
                <path d="M7.646 1.146a.5.5 0 0 1 .708 0l3 3a.5.5 0 0 1-.708.708L8.5 2.707V11.5a.5.5 0 0 1-1 0V2.707L5.354 4.854a.5.5 0 1 1-.708-.708l3-3z"/>
              </svg>&nbsp;&nbsp;&nbsp;
                Upload
              </Button>
            </Form>
            </Card.Body>
            </Card>
            </div>
          )}
      </div>
    </>
  );
};

export default StudentSubArea;