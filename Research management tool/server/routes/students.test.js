const request = require('supertest');
let Student = require('./students');

describe("POST /add", () => {

    describe("when the username and password is missing", () => {
        test("should specify json in the content type header", async () => {
          const bodyData = [
            {username: "username"},
            {password: "password"},
            {}
          ]
          for (const body of bodyData) {
            const response = await request(app).post("/users").send(body)
            expect(response.statusCode).toBe(400)
          }
        })
    })

})