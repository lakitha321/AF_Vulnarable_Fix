import React, { useState, useRef } from 'react';
import { Form, Row, Col, Button } from 'react-bootstrap';
import Dropzone from 'react-dropzone';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const UploadArea = (props) => {
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
            formData.append('title', title);
            formData.append('description', description);
    
            setErrorMsg('');
            await axios.post("http://localhost:8070/assignment/uploadAssignment/", formData, {
              headers: {
                'Content-Type': 'multipart/form-data'
              }
            }).then((res)=>{
              alert(res.data);
              navigate('/submissions');
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

  return (
        <div className="container" align='center' style={{color:'white'}}><br/><br/><br/>
      <Form className="search-form" onSubmit={handleOnSubmit}>
        {errorMsg && <p className="errorMsg">{errorMsg}</p>}
        <Row>
          <Col>
            <Form.Group controlId="title">
              <Form.Control
                type="text"
                name="title"
                value={state.title || ''}
                placeholder="Enter title"
                onChange={handleInputChange}
              />
            </Form.Group>
          </Col>
        </Row>
        <br/>
        <Row>
          <Col>
            <Form.Group controlId="description">
              <Form.Control
                type="text"
                name="description"
                value={state.description || ''}
                placeholder="Enter description"
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
                <p>Drag and drop a file OR click here to select a file</p>
                <br/>
                    {file && (
                    <div>
                        <strong>Selected file:</strong> {file.name}
                    </div>
                    )}
                    {previewSrc ? (
                        isPreviewAvailable ? (
                        <div className="w-50 p-3">
                            <img className='choosedImg' src={previewSrc} alt="Preview" />
                        </div>
                        ) : (
                        <div className="preview-message">
                            <p>No preview available for this file</p>
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
        <Button className="btn btn-success" type="submit" style={{opacity: "70%"}}>
          Upload
        </Button>
      </Form>
      </div>
  );
};

export default UploadArea;