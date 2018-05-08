package demo.webauthn.json

import com.fasterxml.jackson.annotation.JsonInclude.Include
import com.fasterxml.jackson.core.Base64Variants
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.fasterxml.jackson.module.scala.experimental.ScalaObjectMapper


class ScalaJackson {

  def get(): ObjectMapper = {
    val mapper = new ObjectMapper() with ScalaObjectMapper

    mapper.registerModule(DefaultScalaModule)
    mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
    mapper.setSerializationInclusion(Include.NON_ABSENT)
    mapper.registerModule(new Jdk8Module)
    mapper.setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

    mapper
  }

}
