import {
    Body,
    JsonController,
    Post
} from "routing-controllers";
import { Service } from "typedi";
import { OpenAPI } from "routing-controllers-openapi";
import { SuccessResponse, Summary } from 'routing-controllers-openapi-extra';
import {{className}}Service, { InputVerifyDTO, OutputSignInEmailDTO, OutputSignInPhoneDTO, OutputVerifyDTO, SignInEmailDTO, SignInPhoneDTO } from "./{{kebabcase}}.service";


@Service()
@OpenAPI({
    tags: ["{{kebabcase}}"],
})
@JsonController("{{kebabcase}}")
export class {{className}}Controller {
    constructor(public authService: {{className}}Service) { }

    @Summary("SignIn By Email")
    @Post('/email-sign-in')
    @SuccessResponse(OutputSignInEmailDTO)
    async signInByEmail(@Body() data: SignInEmailDTO) {
        return this.authService.signInByEmail(data);
    }

    @Summary("SignIn By Phone")
    @Post('/phone-sign-in')
    @SuccessResponse(OutputSignInPhoneDTO)
    async signInByPhone(@Body() data: SignInPhoneDTO) {
        return this.authService.signInByPhone(data);
    }

    @Summary("Verify Code")
    @Post('/verify')
    @SuccessResponse(OutputVerifyDTO)
    async verify(@Body() data: InputVerifyDTO) {
        return this.authService.verify(data);
    }

}
 