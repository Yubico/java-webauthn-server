package com.yubico.gradle.pitest.tasks

import groovy.xml.XmlUtil

import info.solidsoft.gradle.pitest.PitestTask
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

/**
 * Merges PIT <code>mutations.xml</code> reports from all subprojects into one
 * report in the parent project.
 */
class PitestMergeTask extends DefaultTask {

  @OutputFile
  def File destinationFile = project.file("${project.buildDir}/reports/pitest/mutations.xml")

  PitestMergeTask() {
    project.subprojects.each { subproject ->
      subproject.tasks.withType(PitestTask).each { pitestTask ->
        inputs.files pitestTask.outputs.files
      }
    }
  }

  def Set<File> findMutationsXmlFiles(File f, Set<File> found) {
    if (f.isDirectory()) {
      Set<File> result = found
      for (File child : f.listFiles()) {
        result = findMutationsXmlFiles(child, result)
      }
      return result
    } else if (f.getName().endsWith(".xml")) {
      return found.plus(f)
    } else {
      return found
    }
  }

  def getMutations(File mutationsXmlFile) {
    return new XmlParser().parseText(mutationsXmlFile.text).children()
  }

  @TaskAction
  void merge() {
    Set<File> mutationsXmlFiles = new HashSet<File>()
    inputs.files.each { File f ->
      mutationsXmlFiles = findMutationsXmlFiles(f, mutationsXmlFiles)
    }

    def rootNode = new XmlParser().createNode(null, 'mutations', [:])

    mutationsXmlFiles.each {
      getMutations(it).each { mutation ->
        rootNode.append(mutation)
      }
    }

    if (!destinationFile.exists()) {
      destinationFile.createNewFile()
    }
    def os = destinationFile.newOutputStream()
    XmlUtil.serialize(rootNode, os)
    os.close()
  }

}
